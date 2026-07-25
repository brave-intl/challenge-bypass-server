package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"time"
)

// testSigningKeys holds a key pair for testing
type testSigningKeys struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// setupTestSigningKeys generates a test key pair and adds it to AuthorizedSigners.
// Returns a cleanup function that restores the original signers.
func setupTestSigningKeys() (*testSigningKeys, func()) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}

	keys := &testSigningKeys{
		PublicKey:  pub,
		PrivateKey: priv,
	}

	cleanup := func() {
		AuthorizedSigners = originalSigners
	}

	return keys, cleanup
}

// signedRequest creates an HTTP request with proper signature headers
func (k *testSigningKeys) signedRequest(method, url string, body []byte) (*http.Request, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now()

	// Build the message to sign using path and query
	message := buildSigningMessage(method, req.URL.Path, req.URL.RawQuery, timestamp, body)
	signature := ed25519.Sign(k.PrivateKey, message)

	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(k.PublicKey))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}
