package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	// Header names for signed requests
	HeaderSignature   = "X-Signature"
	HeaderPublicKey   = "X-Public-Key"
	HeaderTimestamp   = "X-Timestamp" // Unix timestamp in seconds (UTC)
	HeaderContentHash = "X-Content-Hash"

	// Maximum age of a signed request (prevents replay attacks)
	// Timestamp validation uses UTC time for consistency
	maxRequestAge = 5 * time.Minute

	// Maximum size of signed request bodies we will accept (currently 1 MiB)
	maxSignedRequestBodySize int64 = 1 << 20
)

var (
	errMissingSignature    = errors.New("missing X-Signature header")
	errMissingPublicKey    = errors.New("missing X-Public-Key header")
	errMissingTimestamp    = errors.New("missing X-Timestamp header")
	errInvalidSignature    = errors.New("invalid signature")
	errInvalidPublicKey    = errors.New("invalid public key format")
	errInvalidTimestamp    = errors.New("invalid timestamp format")
	errRequestExpired      = errors.New("request timestamp expired")
	errRequestFromFuture   = errors.New("request timestamp is in the future")
	errUnauthorizedSigner  = errors.New("public key not in authorized signers list")
	errNoAuthorizedSigners = errors.New("no authorized signers configured")
	errRequestBodyTooLarge = errors.New("request body exceeds allowed size")
)

// AuthorizedSigners is the list of Ed25519 public keys authorized to sign management API requests.
// Each key should be base64-encoded.
// TODO: Replace these placeholder keys with actual authorized public keys before deployment.
var AuthorizedSigners = []string{
	// Example format (replace with real keys):
	// "base64-encoded-ed25519-public-key-1",
	// "base64-encoded-ed25519-public-key-2",
}

// SignedRequest contains the components needed to verify a signed request
type SignedRequest struct {
	Method    string
	Path      string
	RawQuery  string
	Body      []byte
	Timestamp time.Time
	PublicKey ed25519.PublicKey
	Signature []byte
}

func canonicalPathAndQuery(path, rawQuery string) string {
	if rawQuery == "" {
		return path
	}
	return fmt.Sprintf("%s?%s", path, rawQuery)
}

// parseSignedRequest extracts and validates signature components from an HTTP request
func parseSignedRequest(r *http.Request) (*SignedRequest, []byte, error) {
	// Extract required headers
	signatureB64 := r.Header.Get(HeaderSignature)
	if signatureB64 == "" {
		return nil, nil, errMissingSignature
	}

	publicKeyB64 := r.Header.Get(HeaderPublicKey)
	if publicKeyB64 == "" {
		return nil, nil, errMissingPublicKey
	}

	timestampStr := r.Header.Get(HeaderTimestamp)
	if timestampStr == "" {
		return nil, nil, errMissingTimestamp
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errInvalidSignature, err)
	}

	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errInvalidPublicKey, err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: incorrect key length", errInvalidPublicKey)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	// Parse timestamp (Unix timestamp in seconds)
	timestampUnix, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errInvalidTimestamp, err)
	}
	timestamp := time.Unix(timestampUnix, 0)

	// Read request body with an upper bound to prevent resource exhaustion
	limitedReader := io.LimitReader(r.Body, maxSignedRequestBodySize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if int64(len(body)) > maxSignedRequestBodySize {
		return nil, nil, errRequestBodyTooLarge
	}

	// Restore the body for downstream handlers
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	return &SignedRequest{
		Method:    r.Method,
		Path:      r.URL.Path,
		RawQuery:  r.URL.RawQuery,
		Body:      body,
		Timestamp: timestamp,
		PublicKey: publicKey,
		Signature: signature,
	}, body, nil
}

// buildSigningMessage constructs the message that should be signed
// Format: METHOD\nPATH?QUERY\nTIMESTAMP\nBODY
func buildSigningMessage(method, path, rawQuery string, timestamp time.Time, body []byte) []byte {
	timestampStr := strconv.FormatInt(timestamp.Unix(), 10)
	requestTarget := canonicalPathAndQuery(path, rawQuery)
	message := fmt.Sprintf("%s\n%s\n%s\n", method, requestTarget, timestampStr)
	return append([]byte(message), body...)
}

// verifySignature verifies the Ed25519 signature of the request
func (sr *SignedRequest) verifySignature() bool {
	message := buildSigningMessage(sr.Method, sr.Path, sr.RawQuery, sr.Timestamp, sr.Body)
	return ed25519.Verify(sr.PublicKey, message, sr.Signature)
}

// verifyTimestamp checks that the request timestamp is within acceptable bounds
func (sr *SignedRequest) verifyTimestamp() error {
	now := time.Now().UTC()
	age := now.Sub(sr.Timestamp)

	if age > maxRequestAge {
		return errRequestExpired
	}
	if age < -maxRequestAge {
		return errRequestFromFuture
	}
	return nil
}

// isAuthorizedSigner checks if the public key is in the list of authorized signers
func (sr *SignedRequest) isAuthorizedSigner() bool {
	publicKeyB64 := base64.StdEncoding.EncodeToString(sr.PublicKey)
	for _, authorized := range AuthorizedSigners {
		if authorized == publicKeyB64 {
			return true
		}
	}
	return false
}

// VerifySignedRequest verifies that an HTTP request is properly signed by an authorized signer.
// Returns the request body if verification succeeds, or an error if it fails.
func VerifySignedRequest(r *http.Request) ([]byte, error) {
	// Fail if no authorized signers are configured - never allow unauthenticated access
	if len(AuthorizedSigners) == 0 {
		return nil, errNoAuthorizedSigners
	}

	signedReq, body, err := parseSignedRequest(r)
	if err != nil {
		return nil, err
	}

	// Verify timestamp is within acceptable range
	if err := signedReq.verifyTimestamp(); err != nil {
		return nil, err
	}

	// Verify the signer is authorized
	if !signedReq.isAuthorizedSigner() {
		return nil, errUnauthorizedSigner
	}

	// Verify the signature
	if !signedReq.verifySignature() {
		return nil, errInvalidSignature
	}

	return body, nil
}

// verifyManagementRequest is a helper that verifies the request and returns an AppError on failure
func (c *Server) verifyManagementRequest(r *http.Request) ([]byte, *AppError) {
	body, err := VerifySignedRequest(r)
	if err != nil {
		code := http.StatusUnauthorized
		switch {
		case errors.Is(err, errRequestExpired), errors.Is(err, errRequestFromFuture):
			code = http.StatusUnauthorized
		case errors.Is(err, errUnauthorizedSigner):
			code = http.StatusForbidden
		case errors.Is(err, errRequestBodyTooLarge):
			code = http.StatusRequestEntityTooLarge
		case errors.Is(err, errNoAuthorizedSigners):
			code = http.StatusInternalServerError
		}
		return nil, &AppError{
			Message: err.Error(),
			Code:    code,
		}
	}
	return body, nil
}
