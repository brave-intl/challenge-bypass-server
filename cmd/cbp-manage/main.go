package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	// Default server URL
	defaultServerURL = "http://localhost:2416"
)

// IssuerDetail matches the server's IssuerDetailResponse
type IssuerDetail struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Cohort    int16       `json:"cohort"`
	MaxTokens int         `json:"max_tokens"`
	Version   int         `json:"version"`
	ExpiresAt *string     `json:"expires_at,omitempty"`
	CreatedAt *string     `json:"created_at,omitempty"`
	ValidFrom *string     `json:"valid_from,omitempty"`
	Buffer    int         `json:"buffer,omitempty"`
	Overlap   int         `json:"overlap,omitempty"`
	Duration  *string     `json:"duration,omitempty"`
	Keys      []IssuerKey `json:"keys,omitempty"`
}

// IssuerKey matches the server's IssuerKeyResponse
type IssuerKey struct {
	ID        string  `json:"id,omitempty"`
	PublicKey string  `json:"public_key"`
	Cohort    int16   `json:"cohort"`
	StartAt   *string `json:"start_at,omitempty"`
	EndAt     *string `json:"end_at,omitempty"`
	CreatedAt *string `json:"created_at,omitempty"`
}

// IssuerListResponse matches the server's IssuerListResponse
type IssuerListResponse struct {
	Issuers []IssuerDetail `json:"issuers"`
	Total   int            `json:"total"`
}

// Client handles signed requests to the management API
type Client struct {
	ServerURL  string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	HTTPClient *http.Client
}

// NewClient creates a new management API client
func NewClient(serverURL string, privateKey ed25519.PrivateKey) *Client {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &Client{
		ServerURL:  serverURL,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// buildSigningMessage constructs the canonical message to sign
// Format: METHOD\nPATH?QUERY\nTIMESTAMP\nBODY
func buildSigningMessage(method, path, rawQuery string, timestamp time.Time, body []byte) []byte {
	timestampStr := strconv.FormatInt(timestamp.Unix(), 10)

	// Build request target (path with query if present)
	requestTarget := path
	if rawQuery != "" {
		requestTarget = fmt.Sprintf("%s?%s", path, rawQuery)
	}

	message := fmt.Sprintf("%s\n%s\n%s\n", method, requestTarget, timestampStr)
	return append([]byte(message), body...)
}

// SignedRequest performs a signed HTTP request
func (c *Client) SignedRequest(method, path, rawQuery string, body []byte) (*http.Response, error) {
	// Build full URL
	url := c.ServerURL + path
	if rawQuery != "" {
		url = url + "?" + rawQuery
	}

	// Create timestamp
	timestamp := time.Now().UTC()

	// Build signing message
	message := buildSigningMessage(method, path, rawQuery, timestamp, body)

	// Sign the message
	signature := ed25519.Sign(c.PrivateKey, message)

	// Create HTTP request
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add signature headers
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(signature))
	req.Header.Set("X-Public-Key", base64.StdEncoding.EncodeToString(c.PublicKey))
	req.Header.Set("X-Timestamp", strconv.FormatInt(timestamp.Unix(), 10))

	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Execute request
	return c.HTTPClient.Do(req)
}

// ListIssuers retrieves all issuers from the management API
func (c *Client) ListIssuers() (*IssuerListResponse, error) {
	resp, err := c.SignedRequest("GET", "/api/v1/manage/issuers", "", nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result IssuerListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// LoadPrivateKeyFromFile loads an Ed25519 private key from a file
// The file should contain the base64-encoded private key (64 bytes when decoded)
func LoadPrivateKeyFromFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Trim whitespace
	keyB64 := bytes.TrimSpace(data)

	// Decode base64
	keyBytes, err := base64.StdEncoding.DecodeString(string(keyB64))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}

	// Validate key length
	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key length: expected %d bytes, got %d", ed25519.PrivateKeySize, len(keyBytes))
	}

	return ed25519.PrivateKey(keyBytes), nil
}

// GenerateKeyPair generates a new Ed25519 key pair
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "keygen":
		handleKeygen()
	case "list-issuers":
		handleListIssuers()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Challenge Bypass Server Management CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cbp-manage <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  keygen                    Generate a new Ed25519 key pair")
	fmt.Println("  list-issuers              List all issuers")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  CBP_SERVER_URL            Server URL (default: http://localhost:2416)")
	fmt.Println("  CBP_PRIVATE_KEY_FILE      Path to private key file (required for API commands)")
	fmt.Println("  CBP_PRIVATE_KEY           Base64-encoded private key (alternative to file)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Generate a new key pair")
	fmt.Println("  cbp-manage keygen")
	fmt.Println()
	fmt.Println("  # List issuers")
	fmt.Println("  export CBP_PRIVATE_KEY_FILE=~/.cbp/private_key")
	fmt.Println("  cbp-manage list-issuers")
}

func handleKeygen() {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key pair: %v\n", err)
		os.Exit(1)
	}

	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
	privateKeyB64 := base64.StdEncoding.EncodeToString(privateKey)

	fmt.Println("Generated Ed25519 Key Pair")
	fmt.Println()
	fmt.Println("Public Key (add to server's AuthorizedSigners):")
	fmt.Println(publicKeyB64)
	fmt.Println()
	fmt.Println("Private Key (keep secure!):")
	fmt.Println(privateKeyB64)
	fmt.Println()
	fmt.Println("To save the private key:")
	fmt.Printf("  echo '%s' > ~/.cbp/private_key\n", privateKeyB64)
	fmt.Println("  chmod 600 ~/.cbp/private_key")
	fmt.Println()
	fmt.Println("Then export:")
	fmt.Println("  export CBP_PRIVATE_KEY_FILE=~/.cbp/private_key")
}

func handleListIssuers() {
	// Get server URL
	serverURL := os.Getenv("CBP_SERVER_URL")
	if serverURL == "" {
		serverURL = defaultServerURL
	}

	// Load private key
	privateKey, err := loadPrivateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key: %v\n", err)
		fmt.Fprintln(os.Stderr, "\nSet CBP_PRIVATE_KEY_FILE or CBP_PRIVATE_KEY environment variable.")
		fmt.Fprintln(os.Stderr, "Generate a key with: cbp-manage keygen")
		os.Exit(1)
	}

	// Create client
	client := NewClient(serverURL, privateKey)

	// List issuers
	result, err := client.ListIssuers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list issuers: %v\n", err)
		os.Exit(1)
	}

	// Print results
	printIssuers(result)
}

func loadPrivateKey() (ed25519.PrivateKey, error) {
	// Try loading from file first
	if keyFile := os.Getenv("CBP_PRIVATE_KEY_FILE"); keyFile != "" {
		return LoadPrivateKeyFromFile(keyFile)
	}

	// Try loading from environment variable
	if keyB64 := os.Getenv("CBP_PRIVATE_KEY"); keyB64 != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CBP_PRIVATE_KEY: %w", err)
		}

		if len(keyBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid key length: expected %d bytes, got %d", ed25519.PrivateKeySize, len(keyBytes))
		}

		return ed25519.PrivateKey(keyBytes), nil
	}

	return nil, fmt.Errorf("no private key configured")
}

func printIssuers(result *IssuerListResponse) {
	fmt.Printf("Found %d issuer(s)\n\n", result.Total)

	for i, issuer := range result.Issuers {
		fmt.Printf("Issuer %d:\n", i+1)
		fmt.Printf("  ID:         %s\n", issuer.ID)
		fmt.Printf("  Name:       %s\n", issuer.Name)
		fmt.Printf("  Cohort:     %d\n", issuer.Cohort)
		fmt.Printf("  MaxTokens:  %d\n", issuer.MaxTokens)
		fmt.Printf("  Version:    %d\n", issuer.Version)

		if issuer.ExpiresAt != nil {
			fmt.Printf("  ExpiresAt:  %s\n", *issuer.ExpiresAt)
		}
		if issuer.CreatedAt != nil {
			fmt.Printf("  CreatedAt:  %s\n", *issuer.CreatedAt)
		}
		if issuer.ValidFrom != nil {
			fmt.Printf("  ValidFrom:  %s\n", *issuer.ValidFrom)
		}
		if issuer.Buffer > 0 {
			fmt.Printf("  Buffer:     %d\n", issuer.Buffer)
		}
		if issuer.Overlap > 0 {
			fmt.Printf("  Overlap:    %d\n", issuer.Overlap)
		}
		if issuer.Duration != nil {
			fmt.Printf("  Duration:   %s\n", *issuer.Duration)
		}

		if len(issuer.Keys) > 0 {
			fmt.Printf("  Keys:       %d key(s)\n", len(issuer.Keys))
			for j, key := range issuer.Keys {
				fmt.Printf("    Key %d:\n", j+1)
				if key.ID != "" {
					fmt.Printf("      ID:        %s\n", key.ID)
				}
				fmt.Printf("      PublicKey: %s\n", key.PublicKey)
				fmt.Printf("      Cohort:    %d\n", key.Cohort)
				if key.StartAt != nil {
					fmt.Printf("      StartAt:   %s\n", *key.StartAt)
				}
				if key.EndAt != nil {
					fmt.Printf("      EndAt:     %s\n", *key.EndAt)
				}
				if key.CreatedAt != nil {
					fmt.Printf("      CreatedAt: %s\n", *key.CreatedAt)
				}
			}
		}

		if i < len(result.Issuers)-1 {
			fmt.Println()
		}
	}
}
