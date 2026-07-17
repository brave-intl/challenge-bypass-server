package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
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
// Validates checks in order from cheapest to most expensive to fail fast on invalid requests
func parseSignedRequest(r *http.Request) (*SignedRequest, []byte, error) {
	// Step 1: Check for required headers (cheap - no decoding yet)
	timestampStr := r.Header.Get(HeaderTimestamp)
	if timestampStr == "" {
		return nil, nil, errMissingTimestamp
	}

	publicKeyB64 := r.Header.Get(HeaderPublicKey)
	if publicKeyB64 == "" {
		return nil, nil, errMissingPublicKey
	}

	signatureB64 := r.Header.Get(HeaderSignature)
	if signatureB64 == "" {
		return nil, nil, errMissingSignature
	}

	// Step 2: Parse and validate timestamp FIRST (cheap - just parse int and time comparison)
	timestampUnix, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errInvalidTimestamp, err)
	}
	timestamp := time.Unix(timestampUnix, 0)

	// Validate timestamp is within acceptable range (cheap check before expensive operations)
	now := time.Now().UTC()
	age := now.Sub(timestamp)
	if age > maxRequestAge {
		return nil, nil, errRequestExpired
	}
	if age < -maxRequestAge {
		return nil, nil, errRequestFromFuture
	}

	// Step 3: Decode and validate public key (moderately expensive)
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errInvalidPublicKey, err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: incorrect key length", errInvalidPublicKey)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	// Step 4: Read request body (moderately expensive - I/O operation)
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

	// Step 5: Decode signature (moderately expensive - defer until after cheaper checks)
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errInvalidSignature, err)
	}

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

// isAuthorizedSigner checks if the public key is in the list of authorized signers
// Uses constant-time comparison to prevent timing attacks
func (sr *SignedRequest) isAuthorizedSigner() bool {
	publicKeyB64 := base64.StdEncoding.EncodeToString(sr.PublicKey)
	for _, authorized := range AuthorizedSigners {
		// Use constant-time comparison to prevent timing attacks that could
		// leak information about authorized keys through response timing
		if subtle.ConstantTimeCompare([]byte(authorized), []byte(publicKeyB64)) == 1 {
			return true
		}
	}
	return false
}

// VerifySignedRequest verifies that an HTTP request is properly signed by an authorized signer.
// Returns the request body if verification succeeds, or an error if it fails.
// Performs checks in order from cheapest to most expensive for optimal performance.
func VerifySignedRequest(r *http.Request) ([]byte, error) {
	// Step 1: Check if authorized signers are configured (cheapest - single check)
	if len(AuthorizedSigners) == 0 {
		return nil, errNoAuthorizedSigners
	}

	// Step 2-5: Parse request (timestamp validated inside parseSignedRequest)
	signedReq, body, err := parseSignedRequest(r)
	if err != nil {
		return nil, err
	}

	// Step 6: Verify the signer is authorized (cheap - string comparison)
	if !signedReq.isAuthorizedSigner() {
		return nil, errUnauthorizedSigner
	}

	// Step 7: Verify the signature (most expensive - Ed25519 verification, done last)
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
