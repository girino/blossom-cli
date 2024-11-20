// main.go
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: blossom-cli <upload|download|get|list> [options]")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "upload":
		uploadCmd := flag.NewFlagSet("upload", flag.ExitOnError)
		server := uploadCmd.String("server", "", "Blossom server URL")
		filePath := uploadCmd.String("file", "", "File to upload")
		privKey := uploadCmd.String("privkey", "", "Private key for authorization")
		uploadCmd.Parse(os.Args[2:])

		if *server == "" || *filePath == "" || *privKey == "" {
			fmt.Println("Usage: blossom-cli upload -server <server_url> -file <file_path> -privkey <private_key>")
			os.Exit(1)
		}

		err := uploadFile(*server, *filePath, *privKey)
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

	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Usage: blossom-cli <upload|download|get|list> [options]")
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

func uploadFile(server, filePath, privKey string) error {
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

	// Create authorization event
	authEventJSON, err := createAuthorizationEvent(privKey, "upload", [][]string{
		{"x", sha256Hash},
		{"t", "upload"},
		{"expiration", fmt.Sprintf("%d", time.Now().Add(5*time.Minute).Unix())},
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
	req.Header.Set("Content-Type", "application/octet-stream")
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
