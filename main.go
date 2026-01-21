// main.go
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/h2non/filetype"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

var verbose bool

// debugLog prints debug messages only when verbose mode is enabled
func debugLog(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: blossom-cli <upload|download|get|list|mirror> [options]")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "upload":
		uploadCmd := flag.NewFlagSet("upload", flag.ExitOnError)
		server := uploadCmd.String("server", "", "Blossom server URL")
		filePath := uploadCmd.String("file", "", "File to upload")
		privKey := uploadCmd.String("privkey", "", "Private key for authorization")
		expirationStr := uploadCmd.String("expiration", "5m", "Expiration time (e.g., 60s, 5m, 2h). Defaults to 5m. If no unit given, assumes seconds.")
		verboseFlag := uploadCmd.Bool("v", false, "Enable verbose/debug output")
		uploadCmd.Parse(os.Args[2:])
		verbose = *verboseFlag

		if *server == "" || *filePath == "" || *privKey == "" {
			fmt.Println("Usage: blossom-cli upload -server <server_url> -file <file_path> -privkey <private_key> [-expiration <time>]")
			os.Exit(1)
		}

		expiration, err := parseDuration(*expirationStr)
		if err != nil {
			debugLog("Failed to parse expiration: %v", err)
			fmt.Println("Error parsing expiration time:", err)
			os.Exit(1)
		}

		err = uploadFile(*server, *filePath, *privKey, expiration)
		if err != nil {
			debugLog("Upload failed: %v", err)
			fmt.Println("Error uploading file:", err)
			os.Exit(1)
		}

	case "download", "get":
		downloadCmd := flag.NewFlagSet("download", flag.ExitOnError)
		server := downloadCmd.String("server", "", "Blossom server URL")
		hash := downloadCmd.String("hash", "", "SHA256 hash of the file")
		output := downloadCmd.String("output", "", "Output file path")
		verboseFlag := downloadCmd.Bool("v", false, "Enable verbose/debug output")
		downloadCmd.Parse(os.Args[2:])
		verbose = *verboseFlag

		if *server == "" || *hash == "" || *output == "" {
			fmt.Println("Usage: blossom-cli download -server <server_url> -hash <sha256_hash> -output <output_file>")
			os.Exit(1)
		}

		err := downloadFile(*server, *hash, *output)
		if err != nil {
			debugLog("Download failed: %v", err)
			fmt.Println("Error downloading file:", err)
			os.Exit(1)
		}

	case "list":
		listCmd := flag.NewFlagSet("list", flag.ExitOnError)
		server := listCmd.String("server", "", "Blossom server URL")
		pubkey := listCmd.String("pubkey", "", "Public key hex")
		verboseFlag := listCmd.Bool("v", false, "Enable verbose/debug output")
		listCmd.Parse(os.Args[2:])
		verbose = *verboseFlag

		if *server == "" || *pubkey == "" {
			fmt.Println("Usage: blossom-cli list -server <server_url> -pubkey <pubkey>")
			os.Exit(1)
		}

		err := listBlobs(*server, *pubkey)
		if err != nil {
			debugLog("List blobs failed: %v", err)
			fmt.Println("Error listing blobs:", err)
			os.Exit(1)
		}

	case "mirror":
		mirrorCmd := flag.NewFlagSet("mirror", flag.ExitOnError)
		server := mirrorCmd.String("server", "", "Destination Blossom server URL")
		sourceServer := mirrorCmd.String("source-server", "", "Source Blossom server URL where the blob is located")
		hash := mirrorCmd.String("hash", "", "SHA256 hash of the blob")
		blobURL := mirrorCmd.String("url", "", "Full URL of the blob to mirror (extracts source-server and hash from URL)")
		privKey := mirrorCmd.String("privkey", "", "Private key for authorization")
		expirationStr := mirrorCmd.String("expiration", "5m", "Expiration time (e.g., 60s, 5m, 2h). Defaults to 5m. If no unit given, assumes seconds.")
		verboseFlag := mirrorCmd.Bool("v", false, "Enable verbose/debug output")
		mirrorCmd.Parse(os.Args[2:])
		verbose = *verboseFlag

		// Validate mutually exclusive options
		usingURL := *blobURL != ""
		usingServerHash := *sourceServer != "" || *hash != ""

		if usingURL && usingServerHash {
			fmt.Println("Error: Cannot use -url together with -source-server or -hash")
			fmt.Println("Usage: blossom-cli mirror -server <destination_server_url> (-source-server <source_server_url> -hash <sha256_hash> | -url <blob_url>) -privkey <private_key> [-expiration <time>]")
			os.Exit(1)
		}

		if *server == "" || *privKey == "" {
			fmt.Println("Usage: blossom-cli mirror -server <destination_server_url> (-source-server <source_server_url> -hash <sha256_hash> | -url <blob_url>) -privkey <private_key> [-expiration <time>]")
			os.Exit(1)
		}

		var finalSourceServer, finalHash string

		if usingURL {
			// Extract server and hash from URL
			debugLog("Extracting server and hash from URL: %s", *blobURL)
			extractedServer, extractedHash, err := extractServerAndHashFromURL(*blobURL)
			if err != nil {
				debugLog("Failed to extract server and hash: %v", err)
				fmt.Println("Error extracting server and hash from URL:", err)
				os.Exit(1)
			}
			finalSourceServer = extractedServer
			finalHash = extractedHash
			debugLog("Extracted: server=%s, hash=%s", finalSourceServer, finalHash)
		} else {
			// Use provided source-server and hash
			if *sourceServer == "" || *hash == "" {
				fmt.Println("Usage: blossom-cli mirror -server <destination_server_url> (-source-server <source_server_url> -hash <sha256_hash> | -url <blob_url>) -privkey <private_key> [-expiration <time>]")
				os.Exit(1)
			}
			finalSourceServer = *sourceServer
			finalHash = *hash
			debugLog("Using provided: server=%s, hash=%s", finalSourceServer, finalHash)
		}

		expiration, err := parseDuration(*expirationStr)
		if err != nil {
			debugLog("Failed to parse expiration: %v", err)
			fmt.Println("Error parsing expiration time:", err)
			os.Exit(1)
		}

		err = mirrorBlob(*server, finalSourceServer, finalHash, *privKey, expiration)
		if err != nil {
			debugLog("Mirror failed: %v", err)
			fmt.Println("Error mirroring blob:", err)
			os.Exit(1)
		}

	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Usage: blossom-cli <upload|download|get|list|mirror> [options]")
		os.Exit(1)
	}
}

func convertNIP19ToHex(key string) (string, error) {
	debugLog("Converting NIP-19 key to hex (key prefix: %s)", key[:min(4, len(key))])
	if strings.HasPrefix(key, "nsec") {
		_, decoded, err := nip19.Decode(key)
		if err != nil {
			debugLog("Failed to decode NIP-19 key: %v", err)
			return "", fmt.Errorf("failed to decode NIP-19 key: %v", err)
		}
		debugLog("Successfully decoded NIP-19 key (length: %d)", len(decoded.(string)))
		return decoded.(string), nil
	}
	debugLog("Key is already in hex format (length: %d)", len(key))
	return key, nil
}

// parseDuration parses a duration string like "60s", "5m", "2h", etc.
// If no unit is given, assumes seconds.
func parseDuration(s string) (time.Duration, error) {
	debugLog("Parsing duration string: %s", s)
	s = strings.TrimSpace(s)
	if s == "" {
		debugLog("Empty duration string, using default: 5m")
		return 5 * time.Minute, nil
	}

	// Match number and optional unit
	re := regexp.MustCompile(`^(\d+)([smhd]?)$`)
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		debugLog("Invalid duration format: %s (does not match pattern)", s)
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		debugLog("Failed to parse number from duration: %s, error: %v", matches[1], err)
		return 0, fmt.Errorf("invalid number in duration: %s", matches[1])
	}

	unit := matches[2]
	debugLog("Parsed duration: value=%d, unit=%s", value, unit)
	if unit == "" {
		// No unit given, assume seconds
		duration := time.Duration(value) * time.Second
		debugLog("No unit provided, assuming seconds. Duration: %v", duration)
		return duration, nil
	}

	var duration time.Duration
	switch unit {
	case "s":
		duration = time.Duration(value) * time.Second
	case "m":
		duration = time.Duration(value) * time.Minute
	case "h":
		duration = time.Duration(value) * time.Hour
	case "d":
		duration = time.Duration(value) * 24 * time.Hour
	default:
		debugLog("Unknown time unit: %s", unit)
		return 0, fmt.Errorf("unknown time unit: %s", unit)
	}
	debugLog("Parsed duration successfully: %v", duration)
	return duration, nil
}

// Add a function to create the authorization event
func createAuthorizationEvent(privKey string, verb string, tags [][]string) (string, error) {
	debugLog("Creating authorization event: verb=%s, tags_count=%d", verb, len(tags))
	// Create a new event
	event := nostr.Event{
		Kind:      24242,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{},
		Content:   "Upload file",
	}

	// Add the verb tag
	event.Tags = append(event.Tags, nostr.Tag{"t", verb})
	debugLog("Added verb tag: %s", verb)

	// Add additional tags
	for i, tag := range tags {
		event.Tags = append(event.Tags, tag)
		debugLog("Added tag[%d]: %s=%s", i, tag[0], tag[1])
	}

	// Convert the private key from hex
	secKey := privKey
	if strings.HasPrefix(privKey, "nsec") {
		debugLog("Converting NIP-19 private key to hex")
		var err error
		secKey, err = convertNIP19ToHex(privKey)
		if err != nil {
			debugLog("Failed to convert NIP-19 key: %v", err)
			return "", err
		}
	}

	// Set the pubkey
	debugLog("Deriving public key from private key")
	pubKeyHex, err := nostr.GetPublicKey(secKey)
	if err != nil {
		debugLog("Failed to derive public key: %v", err)
		return "", err
	}
	event.PubKey = pubKeyHex
	debugLog("Public key derived: %s", pubKeyHex)

	// Sign the event
	debugLog("Signing event")
	err = event.Sign(secKey)
	if err != nil {
		debugLog("Failed to sign event: %v", err)
		return "", err
	}
	debugLog("Event signed successfully, ID: %s", event.ID)

	// Serialize the event to JSON
	debugLog("Serializing event to JSON")
	eventJSON, err := json.Marshal(event)
	if err != nil {
		debugLog("Failed to marshal event to JSON: %v", err)
		return "", err
	}
	debugLog("Event JSON size: %d bytes", len(eventJSON))

	encodedJSON := base64.StdEncoding.EncodeToString(eventJSON)
	debugLog("Base64 encoded authorization event (length: %d)", len(encodedJSON))
	return encodedJSON, nil
}

func uploadFile(server, filePath, privKey string, expiration time.Duration) error {
	debugLog("Starting upload: server=%s, file=%s, expiration=%v", server, filePath, expiration)

	file, err := os.Open(filePath)
	if err != nil {
		debugLog("Failed to open file %s: %v", filePath, err)
		return err
	}
	defer file.Close()
	debugLog("File opened successfully: %s", filePath)

	// Calculate SHA256
	debugLog("Calculating SHA256 hash")
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		debugLog("Failed to read file for hash calculation: %v", err)
		return err
	}
	sha256Hash := hex.EncodeToString(hasher.Sum(nil))
	debugLog("SHA256 hash calculated: %s", sha256Hash)

	// Reset file pointer
	file.Seek(0, io.SeekStart)

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		debugLog("Failed to get file info: %v", err)
		return err
	}
	debugLog("File size: %d bytes", fileInfo.Size())

	// Read file content to identify MIME type
	debugLog("Detecting MIME type")
	buf := make([]byte, 261)
	_, err = file.Read(buf)
	if err != nil {
		debugLog("Failed to read file for MIME detection: %v", err)
		return err
	}
	kind, err := filetype.Match(buf)
	if err != nil {
		debugLog("Failed to match file type: %v", err)
		return err
	}
	mimeType := kind.MIME.Value
	debugLog("MIME type detected: %s", mimeType)

	// Reset file pointer to the beginning
	file.Seek(0, io.SeekStart)

	// Create authorization event
	expirationUnix := time.Now().Add(expiration).Unix()
	debugLog("Creating authorization event with expiration: %d (unix timestamp)", expirationUnix)
	authEventJSON, err := createAuthorizationEvent(privKey, "upload", [][]string{
		{"x", sha256Hash},
		{"t", "upload"},
		{"expiration", fmt.Sprintf("%d", expirationUnix)},
	})
	if err != nil {
		debugLog("Failed to create authorization event: %v", err)
		return err
	}

	// Create request
	uploadURL := server + "/upload"
	debugLog("Creating PUT request to: %s", uploadURL)
	req, err := http.NewRequest("PUT", uploadURL, file)
	if err != nil {
		debugLog("Failed to create HTTP request: %v", err)
		return err
	}
	req.ContentLength = fileInfo.Size()
	req.Header.Set("Content-Type", mimeType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	req.Header.Set("Authorization", "Nostr "+authEventJSON)
	debugLog("Request headers set: Content-Type=%s, Content-Length=%d", mimeType, fileInfo.Size())

	// Send request
	debugLog("Sending HTTP request")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		debugLog("HTTP request failed: %v", err)
		return err
	}
	defer resp.Body.Close()
	debugLog("HTTP response received: status=%d, headers=%v", resp.StatusCode, resp.Header)

	// Check response
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		debugLog("Upload failed with status %d, response body: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("upload failed: %s", string(bodyBytes))
	}
	debugLog("Upload successful, status code: %d", resp.StatusCode)

	// Parse response
	debugLog("Parsing response JSON")
	var descriptor map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&descriptor)
	if err != nil {
		debugLog("Failed to decode response JSON: %v", err)
		return err
	}
	debugLog("Response parsed successfully")

	// Print blob descriptor
	blobJSON, _ := json.MarshalIndent(descriptor, "", "  ")
	fmt.Println(string(blobJSON))
	return nil
}

func downloadFile(server, hash, outputPath string) error {
	debugLog("Starting download: server=%s, hash=%s, output=%s", server, hash, outputPath)

	// Build URL
	getURL := fmt.Sprintf("%s/%s", server, hash)
	debugLog("Download URL: %s", getURL)

	// Make request
	debugLog("Sending GET request")
	resp, err := http.Get(getURL)
	if err != nil {
		debugLog("HTTP GET request failed: %v", err)
		return err
	}
	defer resp.Body.Close()
	debugLog("HTTP response received: status=%d, headers=%v", resp.StatusCode, resp.Header)

	// Check response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		debugLog("Download failed with status %d, response body: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("download failed: %s", string(bodyBytes))
	}
	debugLog("Download successful, status code: %d, Content-Length: %s", resp.StatusCode, resp.Header.Get("Content-Length"))

	// Create output file
	debugLog("Creating output file: %s", outputPath)
	outFile, err := os.Create(outputPath)
	if err != nil {
		debugLog("Failed to create output file: %v", err)
		return err
	}
	defer outFile.Close()
	debugLog("Output file created successfully")

	// Write to file
	debugLog("Writing response body to file")
	bytesWritten, err := io.Copy(outFile, resp.Body)
	if err != nil {
		debugLog("Failed to write file: %v", err)
		return err
	}
	debugLog("File written successfully: %d bytes", bytesWritten)

	fmt.Println("File downloaded successfully.")
	return nil
}

func listBlobs(server, pubkey string) error {
	debugLog("Listing blobs: server=%s, pubkey=%s", server, pubkey)
	listURL := fmt.Sprintf("%s/list/%s", server, pubkey)
	debugLog("List URL: %s", listURL)

	// Make request
	debugLog("Sending GET request")
	resp, err := http.Get(listURL)
	if err != nil {
		debugLog("HTTP GET request failed: %v", err)
		return err
	}
	defer resp.Body.Close()
	debugLog("HTTP response received: status=%d, headers=%v", resp.StatusCode, resp.Header)

	// Read the response body
	debugLog("Reading response body")
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		debugLog("Failed to read response body: %v", err)
		fmt.Println("Error reading response:", err)
		return err
	}
	debugLog("Response body read: %d bytes", len(bodyBytes))
	bodyStr := string(bodyBytes)

	// Check if the response starts with '[' and ends with ']'
	// If not, wrap it to make it a valid JSON array
	debugLog("Normalizing JSON response")
	bodyStr = strings.TrimSpace(bodyStr)
	originalLength := len(bodyStr)
	bodyStr = strings.ReplaceAll(bodyStr, "\n", "")
	bodyStr = strings.ReplaceAll(bodyStr, "\r", "")
	if !strings.HasPrefix(bodyStr, "[") {
		debugLog("Response doesn't start with '[', prepending it")
		bodyStr = "[" + bodyStr
	}
	if !strings.HasSuffix(bodyStr, "]") {
		debugLog("Response doesn't end with ']', appending it")
		bodyStr = bodyStr + "]"
	}
	debugLog("JSON normalized: original_length=%d, normalized_length=%d", originalLength, len(bodyStr))

	// Insert commas between JSON objects if missing
	debugLog("Inserting commas between JSON objects if needed")
	bodyStr = insertCommas(bodyStr)
	debugLog("Commas inserted, final length: %d", len(bodyStr))

	// Parse the fixed JSON
	debugLog("Parsing JSON array")
	var descriptors []map[string]interface{}
	err = json.Unmarshal([]byte(bodyStr), &descriptors)
	if err != nil {
		debugLog("Failed to parse JSON: %v, body preview: %s", err, bodyStr[:min(200, len(bodyStr))])
		fmt.Println("Error decoding response:", err)
		return err
	}
	debugLog("JSON parsed successfully: %d descriptors found", len(descriptors))

	// Print blob descriptors
	blobsJSON, _ := json.MarshalIndent(descriptors, "", "  ")
	fmt.Println("Parsed Blobs:")
	fmt.Println(string(blobsJSON))
	return nil
}

// Function to insert commas between JSON objects in an array if missing
func insertCommas(jsonStr string) string {
	var result strings.Builder
	inQuotes := false
	braceStack := 0

	for i, c := range jsonStr {
		result.WriteRune(c)

		switch c {
		case '"':
			// Toggle inQuotes when a double-quote is found
			inQuotes = !inQuotes
		case '{':
			if !inQuotes {
				braceStack++
			}
		case '}':
			if !inQuotes {
				braceStack--
				if braceStack == 0 && i+1 < len(jsonStr) && jsonStr[i+1] == '{' {
					// Insert comma if the next character is '{' and we're not inside braces
					result.WriteString(",")
				}
			}
		}
	}

	return result.String()
}

// extractServerAndHashFromURL extracts the server base URL and hash from a full blob URL
// Example: https://cdn.satellite.earth/b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553.pdf
// Returns: https://cdn.satellite.earth, b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553
func extractServerAndHashFromURL(blobURL string) (string, string, error) {
	debugLog("Extracting server and hash from URL: %s", blobURL)
	parsedURL, err := url.Parse(blobURL)
	if err != nil {
		debugLog("Failed to parse URL: %v", err)
		return "", "", fmt.Errorf("invalid URL: %v", err)
	}
	debugLog("URL parsed: scheme=%s, host=%s, path=%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)

	// Get the base server URL (scheme + host, which already includes port if present)
	serverURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	debugLog("Extracted server URL: %s", serverURL)

	// Get the path and extract hash from it
	path := parsedURL.Path
	base := filepath.Base(path)
	debugLog("Path base: %s", base)

	// Remove file extension if present
	baseWithoutExt := strings.TrimSuffix(base, filepath.Ext(base))
	if baseWithoutExt != base {
		debugLog("Removed file extension, base without ext: %s", baseWithoutExt)
	}

	// Check if the base (without extension) is a 64-character hex string
	hashRegex := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	if hashRegex.MatchString(baseWithoutExt) {
		hash := strings.ToLower(baseWithoutExt)
		debugLog("Found hash in filename: %s", hash)
		return serverURL, hash, nil
	}

	// Also check if there's a hash in the path segments
	debugLog("Hash not found in filename, checking path segments")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	debugLog("Path segments: %v", pathParts)
	for _, part := range pathParts {
		partWithoutExt := strings.TrimSuffix(part, filepath.Ext(part))
		if hashRegex.MatchString(partWithoutExt) {
			hash := strings.ToLower(partWithoutExt)
			debugLog("Found hash in path segment: %s", hash)
			return serverURL, hash, nil
		}
	}

	debugLog("Could not find SHA256 hash in URL path: %s", blobURL)
	return "", "", fmt.Errorf("could not find SHA256 hash in URL path: %s", blobURL)
}

func mirrorBlob(server, sourceServer, hash, privKey string, expiration time.Duration) error {
	debugLog("Starting mirror: destination_server=%s, source_server=%s, hash=%s, expiration=%v", server, sourceServer, hash, expiration)

	// Construct the blob URL from source server and hash
	blobURL := strings.TrimSuffix(sourceServer, "/") + "/" + hash
	debugLog("Constructed blob URL: %s", blobURL)

	// Create authorization event with the hash
	expirationUnix := time.Now().Add(expiration).Unix()
	debugLog("Creating authorization event with expiration: %d (unix timestamp)", expirationUnix)
	authEventJSON, err := createAuthorizationEvent(privKey, "upload", [][]string{
		{"x", hash},
		{"t", "upload"},
		{"expiration", fmt.Sprintf("%d", expirationUnix)},
	})
	if err != nil {
		debugLog("Failed to create authorization event: %v", err)
		return err
	}

	// Create JSON body with the URL
	debugLog("Creating request body")
	requestBody := map[string]string{
		"url": blobURL,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		debugLog("Failed to marshal request body: %v", err)
		return err
	}
	debugLog("Request body created: %s", string(jsonBody))

	// Create request
	mirrorURL := strings.TrimSuffix(server, "/") + "/mirror"
	debugLog("Creating PUT request to: %s", mirrorURL)
	req, err := http.NewRequest("PUT", mirrorURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		debugLog("Failed to create HTTP request: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Nostr "+authEventJSON)
	debugLog("Request headers set: Content-Type=application/json, Authorization header length=%d", len(authEventJSON))

	// Send request
	debugLog("Sending HTTP request")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		debugLog("HTTP request failed: %v", err)
		return err
	}
	defer resp.Body.Close()
	debugLog("HTTP response received: status=%d, headers=%v", resp.StatusCode, resp.Header)

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		debugLog("Mirror failed with status %d, response body: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("mirror failed (status %d): %s", resp.StatusCode, string(bodyBytes))
	}
	debugLog("Mirror successful, status code: %d", resp.StatusCode)

	// Parse response
	debugLog("Parsing response JSON")
	var descriptor map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&descriptor)
	if err != nil {
		debugLog("Failed to decode response JSON: %v", err)
		return err
	}
	debugLog("Response parsed successfully")

	// Print blob descriptor
	blobJSON, _ := json.MarshalIndent(descriptor, "", "  ")
	fmt.Println(string(blobJSON))
	return nil
}
