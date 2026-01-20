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
		uploadCmd.Parse(os.Args[2:])

		if *server == "" || *filePath == "" || *privKey == "" {
			fmt.Println("Usage: blossom-cli upload -server <server_url> -file <file_path> -privkey <private_key> [-expiration <time>]")
			os.Exit(1)
		}

		expiration, err := parseDuration(*expirationStr)
		if err != nil {
			fmt.Println("Error parsing expiration time:", err)
			os.Exit(1)
		}

		err = uploadFile(*server, *filePath, *privKey, expiration)
		if err != nil {
			fmt.Println("Error uploading file:", err)
			os.Exit(1)
		}

	case "download", "get":
		downloadCmd := flag.NewFlagSet("download", flag.ExitOnError)
		server := downloadCmd.String("server", "", "Blossom server URL")
		hash := downloadCmd.String("hash", "", "SHA256 hash of the file")
		output := downloadCmd.String("output", "", "Output file path")
		downloadCmd.Parse(os.Args[2:])

		if *server == "" || *hash == "" || *output == "" {
			fmt.Println("Usage: blossom-cli download -server <server_url> -hash <sha256_hash> -output <output_file>")
			os.Exit(1)
		}

		err := downloadFile(*server, *hash, *output)
		if err != nil {
			fmt.Println("Error downloading file:", err)
			os.Exit(1)
		}

	case "list":
		listCmd := flag.NewFlagSet("list", flag.ExitOnError)
		server := listCmd.String("server", "", "Blossom server URL")
		pubkey := listCmd.String("pubkey", "", "Public key hex")
		listCmd.Parse(os.Args[2:])

		if *server == "" || *pubkey == "" {
			fmt.Println("Usage: blossom-cli list -server <server_url> -pubkey <pubkey>")
			os.Exit(1)
		}

		err := listBlobs(*server, *pubkey)
		if err != nil {
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
		mirrorCmd.Parse(os.Args[2:])

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
			extractedServer, extractedHash, err := extractServerAndHashFromURL(*blobURL)
			if err != nil {
				fmt.Println("Error extracting server and hash from URL:", err)
				os.Exit(1)
			}
			finalSourceServer = extractedServer
			finalHash = extractedHash
		} else {
			// Use provided source-server and hash
			if *sourceServer == "" || *hash == "" {
				fmt.Println("Usage: blossom-cli mirror -server <destination_server_url> (-source-server <source_server_url> -hash <sha256_hash> | -url <blob_url>) -privkey <private_key> [-expiration <time>]")
				os.Exit(1)
			}
			finalSourceServer = *sourceServer
			finalHash = *hash
		}

		expiration, err := parseDuration(*expirationStr)
		if err != nil {
			fmt.Println("Error parsing expiration time:", err)
			os.Exit(1)
		}

		err = mirrorBlob(*server, finalSourceServer, finalHash, *privKey, expiration)
		if err != nil {
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
	if strings.HasPrefix(key, "nsec") {
		_, decoded, err := nip19.Decode(key)
		if err != nil {
			return "", fmt.Errorf("failed to decode NIP-19 key: %v", err)
		}
		return decoded.(string), nil
	}
	return key, nil
}

// parseDuration parses a duration string like "60s", "5m", "2h", etc.
// If no unit is given, assumes seconds.
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 5 * time.Minute, nil
	}

	// Match number and optional unit
	re := regexp.MustCompile(`^(\d+)([smhd]?)$`)
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid number in duration: %s", matches[1])
	}

	unit := matches[2]
	if unit == "" {
		// No unit given, assume seconds
		return time.Duration(value) * time.Second, nil
	}

	switch unit {
	case "s":
		return time.Duration(value) * time.Second, nil
	case "m":
		return time.Duration(value) * time.Minute, nil
	case "h":
		return time.Duration(value) * time.Hour, nil
	case "d":
		return time.Duration(value) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown time unit: %s", unit)
	}
}

// Add a function to create the authorization event
func createAuthorizationEvent(privKey string, verb string, tags [][]string) (string, error) {
	// Create a new event
	event := nostr.Event{
		Kind:      24242,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{},
		Content:   "Upload file",
	}

	// Add the verb tag
	event.Tags = append(event.Tags, nostr.Tag{"t", verb})

	// Add additional tags
	for _, tag := range tags {
		event.Tags = append(event.Tags, tag)
	}

	// Convert the private key from hex
	secKey := privKey
	if strings.HasPrefix(privKey, "nsec") {
		var err error
		secKey, err = convertNIP19ToHex(privKey)
		if err != nil {
			return "", err
		}
	}

	// Set the pubkey
	pubKeyHex, err := nostr.GetPublicKey(secKey)
	if err != nil {
		return "", err
	}
	event.PubKey = pubKeyHex

	// Sign the event
	err = event.Sign(secKey)
	if err != nil {
		return "", err
	}

	// Serialize the event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	encodedJSON := base64.StdEncoding.EncodeToString(eventJSON)
	return encodedJSON, nil
}

func uploadFile(server, filePath, privKey string, expiration time.Duration) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Calculate SHA256
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	// Reset file pointer
	file.Seek(0, io.SeekStart)

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	// Read file content to identify MIME type
	buf := make([]byte, 261)
	_, err = file.Read(buf)
	if err != nil {
		return err
	}
	kind, err := filetype.Match(buf)
	if err != nil {
		return err
	}
	mimeType := kind.MIME.Value

	// Reset file pointer to the beginning
	file.Seek(0, io.SeekStart)

	// Create authorization event
	authEventJSON, err := createAuthorizationEvent(privKey, "upload", [][]string{
		{"x", sha256Hash},
		{"t", "upload"},
		{"expiration", fmt.Sprintf("%d", time.Now().Add(expiration).Unix())},
	})
	if err != nil {
		return err
	}

	// Create request
	uploadURL := server + "/upload"
	req, err := http.NewRequest("PUT", uploadURL, file)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mimeType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	req.Header.Set("Authorization", "Nostr "+authEventJSON)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed: %s", string(bodyBytes))
	}

	// Parse response
	var descriptor map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&descriptor)
	if err != nil {
		return err
	}

	// Print blob descriptor
	blobJSON, _ := json.MarshalIndent(descriptor, "", "  ")
	fmt.Println(string(blobJSON))
	return nil
}

func downloadFile(server, hash, outputPath string) error {
	// Build URL
	getURL := fmt.Sprintf("%s/%s", server, hash)

	// Make request
	resp, err := http.Get(getURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed: %s", string(bodyBytes))
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Write to file
	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return err
	}

	fmt.Println("File downloaded successfully.")
	return nil
}

func listBlobs(server, pubkey string) error {
	listURL := fmt.Sprintf("%s/list/%s", server, pubkey)

	// Make request
	resp, err := http.Get(listURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return err
	}
	bodyStr := string(bodyBytes)

	// Check if the response starts with '[' and ends with ']'
	// If not, wrap it to make it a valid JSON array
	bodyStr = strings.TrimSpace(bodyStr)
	bodyStr = strings.ReplaceAll(bodyStr, "\n", "")
	bodyStr = strings.ReplaceAll(bodyStr, "\r", "")
	if !strings.HasPrefix(bodyStr, "[") {
		bodyStr = "[" + bodyStr
	}
	if !strings.HasSuffix(bodyStr, "]") {
		bodyStr = bodyStr + "]"
	}

	// Insert commas between JSON objects if missing
	bodyStr = insertCommas(bodyStr)

	// Parse the fixed JSON
	var descriptors []map[string]interface{}
	err = json.Unmarshal([]byte(bodyStr), &descriptors)
	if err != nil {
		fmt.Println("Error decoding response:", err)
		return err
	}

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
	parsedURL, err := url.Parse(blobURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %v", err)
	}

	// Get the base server URL (scheme + host, which already includes port if present)
	serverURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Get the path and extract hash from it
	path := parsedURL.Path
	base := filepath.Base(path)

	// Remove file extension if present
	baseWithoutExt := strings.TrimSuffix(base, filepath.Ext(base))

	// Check if the base (without extension) is a 64-character hex string
	hashRegex := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	if hashRegex.MatchString(baseWithoutExt) {
		return serverURL, strings.ToLower(baseWithoutExt), nil
	}

	// Also check if there's a hash in the path segments
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	for _, part := range pathParts {
		partWithoutExt := strings.TrimSuffix(part, filepath.Ext(part))
		if hashRegex.MatchString(partWithoutExt) {
			return serverURL, strings.ToLower(partWithoutExt), nil
		}
	}

	return "", "", fmt.Errorf("could not find SHA256 hash in URL path: %s", blobURL)
}

func mirrorBlob(server, sourceServer, hash, privKey string, expiration time.Duration) error {
	// Construct the blob URL from source server and hash
	blobURL := strings.TrimSuffix(sourceServer, "/") + "/" + hash

	// Create authorization event with the hash
	authEventJSON, err := createAuthorizationEvent(privKey, "upload", [][]string{
		{"x", hash},
		{"t", "upload"},
		{"expiration", fmt.Sprintf("%d", time.Now().Add(expiration).Unix())},
	})
	if err != nil {
		return err
	}

	// Create JSON body with the URL
	requestBody := map[string]string{
		"url": blobURL,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	// Create request
	mirrorURL := strings.TrimSuffix(server, "/") + "/mirror"
	req, err := http.NewRequest("PUT", mirrorURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Nostr "+authEventJSON)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mirror failed (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var descriptor map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&descriptor)
	if err != nil {
		return err
	}

	// Print blob descriptor
	blobJSON, _ := json.MarshalIndent(descriptor, "", "  ")
	fmt.Println(string(blobJSON))
	return nil
}
