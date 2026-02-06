package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to generate a test key pair
func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return pub, priv
}

// Helper to sign a request
func signRequest(t *testing.T, method, path, rawQuery string, body []byte, timestamp time.Time, privateKey ed25519.PrivateKey) []byte {
	message := buildSigningMessage(method, path, rawQuery, timestamp, body)
	return ed25519.Sign(privateKey, message)
}

// Helper to create a signed HTTP request
func createSignedRequest(t *testing.T, method, path, rawQuery string, body []byte, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, timestamp time.Time) *http.Request {
	target := path
	if rawQuery != "" {
		target = path + "?" + rawQuery
	}

	req := httptest.NewRequest(method, target, bytes.NewReader(body))

	signature := signRequest(t, method, path, rawQuery, body, timestamp, privateKey)

	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(publicKey))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

	return req
}

func TestBuildSigningMessage(t *testing.T) {
	timestamp := time.Unix(1234567890, 0)
	body := []byte(`{"test": "data"}`)

	message := buildSigningMessage("POST", "/api/v1/test", "", timestamp, body)

	expected := "POST\n/api/v1/test\n1234567890\n{\"test\": \"data\"}"
	assert.Equal(t, expected, string(message))
}

func TestBuildSigningMessage_EmptyBody(t *testing.T) {
	timestamp := time.Unix(1234567890, 0)

	message := buildSigningMessage("GET", "/api/v1/test", "", timestamp, []byte{})

	expected := "GET\n/api/v1/test\n1234567890\n"
	assert.Equal(t, expected, string(message))
}

func TestBuildSigningMessage_WithQuery(t *testing.T) {
	timestamp := time.Unix(1234567890, 0)

	message := buildSigningMessage("DELETE", "/api/v1/manage/issuers/123", "force=true", timestamp, []byte{})

	expected := "DELETE\n/api/v1/manage/issuers/123?force=true\n1234567890\n"
	assert.Equal(t, expected, string(message))
}

func TestVerifySignedRequest_NoAuthorizedSigners(t *testing.T) {
	// When no signers are configured, all requests should fail
	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader(body))

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errNoAuthorizedSigners)
}

func TestVerifySignedRequest_ValidSignature(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	// Add the public key to authorized signers
	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now()

	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub, priv, timestamp)

	result, err := VerifySignedRequest(req)

	require.NoError(t, err)
	assert.Equal(t, body, result)
}

func TestVerifySignedRequest_ValidSignatureWithQuery(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now()

	req := createSignedRequest(t, "POST", "/api/v1/manage/issuers/123", "force=true", body, pub, priv, timestamp)

	result, err := VerifySignedRequest(req)

	require.NoError(t, err)
	assert.Equal(t, body, result)
}

func TestVerifySignedRequest_MissingSignatureHeader(t *testing.T) {
	pub, _ := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader([]byte(`{}`)))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(pub))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	// Missing X-Signature header

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errMissingSignature)
}

func TestVerifySignedRequest_MissingPublicKeyHeader(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{}`)
	timestamp := time.Now()
	signature := signRequest(t, "POST", "/api/v1/test", "", body, timestamp, priv)

	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader(body))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))
	// Missing X-Public-Key header

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errMissingPublicKey)
}

func TestVerifySignedRequest_MissingTimestampHeader(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{}`)
	timestamp := time.Now()
	signature := signRequest(t, "POST", "/api/v1/test", "", body, timestamp, priv)

	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader(body))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(pub))
	// Missing X-Timestamp header

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errMissingTimestamp)
}

func TestVerifySignedRequest_InvalidSignature(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now()

	// Sign with correct body but send different body
	signature := signRequest(t, "POST", "/api/v1/test", "", body, timestamp, priv)

	differentBody := []byte(`{"test": "tampered"}`)
	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader(differentBody))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(pub))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidSignature)
}

func TestVerifySignedRequest_UnauthorizedSigner(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	otherPub, _ := generateTestKeyPair(t)

	// Only authorize a different key
	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(otherPub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now()

	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub, priv, timestamp)

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errUnauthorizedSigner)
}

func TestVerifySignedRequest_ExpiredTimestamp(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	// Timestamp from 10 minutes ago (beyond maxRequestAge)
	timestamp := time.Now().Add(-10 * time.Minute)

	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub, priv, timestamp)

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errRequestExpired)
}

func TestVerifySignedRequest_FutureTimestamp(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	// Timestamp from 10 minutes in the future (beyond maxRequestAge)
	timestamp := time.Now().Add(10 * time.Minute)

	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub, priv, timestamp)

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errRequestFromFuture)
}

func TestVerifySignedRequest_InvalidPublicKeyFormat(t *testing.T) {
	pub, _ := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader([]byte(`{}`)))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString([]byte("signature")))
	req.Header.Set(HeaderPublicKey, "not-valid-base64!!!")
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidPublicKey)
}

func TestVerifySignedRequest_WrongPublicKeyLength(t *testing.T) {
	pub, _ := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader([]byte(`{}`)))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString([]byte("signature")))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString([]byte("short"))) // Wrong length
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidPublicKey)
}

func TestVerifySignedRequest_InvalidTimestampFormat(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{}`)
	signature := signRequest(t, "POST", "/api/v1/test", "", body, time.Now(), priv)

	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader(body))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(pub))
	req.Header.Set(HeaderTimestamp, "not-a-number")

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidTimestamp)
}

func TestVerifySignedRequest_BodyIsRestored(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now()

	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub, priv, timestamp)

	_, err := VerifySignedRequest(req)
	require.NoError(t, err)

	// Body should still be readable
	restoredBody, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, restoredBody)
}

func TestVerifySignedRequest_DifferentMethod(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{}`)
	timestamp := time.Now()

	// Sign as POST but send as DELETE
	signature := signRequest(t, "POST", "/api/v1/test", "", body, timestamp, priv)

	req := httptest.NewRequest("DELETE", "/api/v1/test", bytes.NewReader(body))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(pub))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidSignature)
}

func TestVerifySignedRequest_DifferentPath(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{}`)
	timestamp := time.Now()

	// Sign for one path but send to different path
	signature := signRequest(t, "POST", "/api/v1/original", "", body, timestamp, priv)

	req := httptest.NewRequest("POST", "/api/v1/different", bytes.NewReader(body))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(pub))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidSignature)
}

func TestVerifySignedRequest_DifferentQuery(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{}`)
	timestamp := time.Now()

	signature := signRequest(t, "POST", "/api/v1/test", "force=true", body, timestamp, priv)

	req := httptest.NewRequest("POST", "/api/v1/test?force=false", bytes.NewReader(body))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(pub))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

	_, err := VerifySignedRequest(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidSignature)
}

func TestVerifySignedRequest_MultipleAuthorizedSigners(t *testing.T) {
	pub1, _ := generateTestKeyPair(t)
	pub2, priv2 := generateTestKeyPair(t)
	pub3, _ := generateTestKeyPair(t)

	// Authorize multiple keys
	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{
		base64.StdEncoding.EncodeToString(pub1),
		base64.StdEncoding.EncodeToString(pub2),
		base64.StdEncoding.EncodeToString(pub3),
	}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now()

	// Sign with the second key
	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub2, priv2, timestamp)

	result, err := VerifySignedRequest(req)

	require.NoError(t, err)
	assert.Equal(t, body, result)
}

func TestVerifyManagementRequest_Success(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now()

	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub, priv, timestamp)

	srv := &Server{}
	result, appErr := srv.verifyManagementRequest(req)

	assert.Nil(t, appErr)
	assert.Equal(t, body, result)
}

func TestVerifyManagementRequest_Unauthorized(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	otherPub, _ := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(otherPub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now()

	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub, priv, timestamp)

	srv := &Server{}
	_, appErr := srv.verifyManagementRequest(req)

	require.NotNil(t, appErr)
	assert.Equal(t, http.StatusForbidden, appErr.Code)
}

func TestVerifyManagementRequest_ExpiredRequest(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(pub)}
	defer func() { AuthorizedSigners = originalSigners }()

	body := []byte(`{"test": "data"}`)
	timestamp := time.Now().Add(-10 * time.Minute)

	req := createSignedRequest(t, "POST", "/api/v1/test", "", body, pub, priv, timestamp)

	srv := &Server{}
	_, appErr := srv.verifyManagementRequest(req)

	require.NotNil(t, appErr)
	assert.Equal(t, http.StatusUnauthorized, appErr.Code)
}
