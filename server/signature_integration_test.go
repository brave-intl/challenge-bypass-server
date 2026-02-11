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

// TestSignatureVerificationIntegration tests the full signature verification flow
// from HTTP request through middleware to handler
func TestSignatureVerificationIntegration(t *testing.T) {
	// Generate a test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Setup authorized signers
	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(publicKey)}
	defer func() { AuthorizedSigners = originalSigners }()

	// Create a test server with a simple handler
	handlerCalled := false
	var receivedBody string
	srv := &Server{}
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Test successful signature verification
	t.Run("ValidSignature", func(t *testing.T) {
		handlerCalled = false
		receivedBody = ""

		method := "POST"
		path := "/api/v1/manage/issuers"
		body := []byte(`{"name":"test","cohort":1}`)
		timestamp := time.Now().UTC()

		// Sign the request
		message := buildSigningMessage(method, path, "", timestamp, body)
		signature := ed25519.Sign(privateKey, message)

		// Create HTTP request
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(publicKey))
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

		w := httptest.NewRecorder()

		// Wrap handler with signature verification
		verifyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := srv.verifyManagementRequest(r)
			if err != nil {
				http.Error(w, err.Message, err.Code)
				return
			}
			testHandler.ServeHTTP(w, r)
		})

		verifyHandler.ServeHTTP(w, req)

		assert.True(t, handlerCalled, "Handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, `{"name":"test","cohort":1}`, receivedBody)
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		handlerCalled = false

		method := "POST"
		path := "/api/v1/manage/issuers"
		body := []byte(`{"name":"test"}`)
		timestamp := time.Now().UTC()

		// Create WRONG signature (sign different message)
		wrongMessage := buildSigningMessage("GET", path, "", timestamp, body)
		signature := ed25519.Sign(privateKey, wrongMessage)

		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(publicKey))
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

		w := httptest.NewRecorder()

		verifyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := srv.verifyManagementRequest(r)
			if err != nil {
				http.Error(w, err.Message, err.Code)
				return
			}
			testHandler.ServeHTTP(w, r)
		})

		verifyHandler.ServeHTTP(w, req)

		assert.False(t, handlerCalled, "Handler should not be called")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("ExpiredTimestamp", func(t *testing.T) {
		handlerCalled = false

		method := "POST"
		path := "/api/v1/manage/issuers"
		body := []byte(`{"name":"test"}`)
		// Use old timestamp (10 minutes ago)
		timestamp := time.Now().UTC().Add(-10 * time.Minute)

		message := buildSigningMessage(method, path, "", timestamp, body)
		signature := ed25519.Sign(privateKey, message)

		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(publicKey))
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

		w := httptest.NewRecorder()

		verifyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := srv.verifyManagementRequest(r)
			if err != nil {
				http.Error(w, err.Message, err.Code)
				return
			}
			testHandler.ServeHTTP(w, r)
		})

		verifyHandler.ServeHTTP(w, req)

		assert.False(t, handlerCalled, "Handler should not be called")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("UnauthorizedPublicKey", func(t *testing.T) {
		handlerCalled = false

		// Generate a different key pair (not in AuthorizedSigners)
		unauthorizedPublic, unauthorizedPrivate, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		method := "POST"
		path := "/api/v1/manage/issuers"
		body := []byte(`{"name":"test"}`)
		timestamp := time.Now().UTC()

		message := buildSigningMessage(method, path, "", timestamp, body)
		signature := ed25519.Sign(unauthorizedPrivate, message)

		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(unauthorizedPublic))
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

		w := httptest.NewRecorder()

		verifyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := srv.verifyManagementRequest(r)
			if err != nil {
				http.Error(w, err.Message, err.Code)
				return
			}
			testHandler.ServeHTTP(w, r)
		})

		verifyHandler.ServeHTTP(w, req)

		assert.False(t, handlerCalled, "Handler should not be called")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("WithQueryParameters", func(t *testing.T) {
		handlerCalled = false

		method := "DELETE"
		path := "/api/v1/manage/issuers/123"
		query := "force=true"
		body := []byte{}
		timestamp := time.Now().UTC()

		// Sign with query parameters included
		message := buildSigningMessage(method, path, query, timestamp, body)
		signature := ed25519.Sign(privateKey, message)

		req := httptest.NewRequest(method, path+"?"+query, bytes.NewReader(body))
		req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(publicKey))
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

		w := httptest.NewRecorder()

		verifyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := srv.verifyManagementRequest(r)
			if err != nil {
				http.Error(w, err.Message, err.Code)
				return
			}
			testHandler.ServeHTTP(w, r)
		})

		verifyHandler.ServeHTTP(w, req)

		assert.True(t, handlerCalled, "Handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("BodyRestoration", func(t *testing.T) {
		// Test that body can be read multiple times after verification
		method := "POST"
		path := "/api/v1/manage/issuers"
		body := []byte(`{"name":"test","cohort":1}`)
		timestamp := time.Now().UTC()

		message := buildSigningMessage(method, path, "", timestamp, body)
		signature := ed25519.Sign(privateKey, message)

		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(publicKey))
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

		// First read during verification
		_, appErr := srv.verifyManagementRequest(req)
		if appErr != nil {
			t.Fatalf("Verification failed: %v (code: %d, message: %s)", appErr, appErr.Code, appErr.Message)
		}

		// Body should still be readable
		bodyBytes := make([]byte, len(body))
		n, readErr := req.Body.Read(bodyBytes)
		// Body was consumed and restored - EOF indicates successful read of restored body
		if readErr != nil && readErr != io.EOF {
			t.Fatalf("Unexpected read error: %v", readErr)
		}
		assert.Equal(t, len(body), n)
		assert.Equal(t, body, bodyBytes)
	})
}

// TestSignatureVerificationWithRateLimiting tests the full flow including rate limiting
func TestSignatureVerificationWithRateLimiting(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(publicKey)}
	defer func() { AuthorizedSigners = originalSigners }()

	srv := &Server{}
	requestCount := 0
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	})

	// Create rate limiter with low limit for testing
	rateLimiter := NewRateLimiter(3, 1*time.Minute)

	// Wrap with both rate limiting and signature verification
	handler := srv.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := srv.verifyManagementRequest(r)
		if err != nil {
			http.Error(w, err.Message, err.Code)
			return
		}
		testHandler.ServeHTTP(w, r)
	}))

	method := "GET"
	path := "/api/v1/manage/issuers"
	body := []byte{}
	timestamp := time.Now().UTC()

	message := buildSigningMessage(method, path, "", timestamp, body)
	signature := ed25519.Sign(privateKey, message)

	// First 3 requests should succeed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(publicKey))
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
	}

	// 4th request should be rate limited
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(publicKey))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp.Unix(), 10))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited")
	assert.Equal(t, 3, requestCount, "Only 3 requests should reach handler")
}

// TestSignatureVerificationErrorCases tests various error scenarios
func TestSignatureVerificationErrorCases(t *testing.T) {
	// Setup test signing key
	publicKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	originalSigners := AuthorizedSigners
	AuthorizedSigners = []string{base64.StdEncoding.EncodeToString(publicKey)}
	defer func() { AuthorizedSigners = originalSigners }()

	srv := &Server{}

	testCases := []struct {
		name           string
		setupHeaders   func(*http.Request)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "MissingSignatureHeader",
			setupHeaders: func(req *http.Request) {
				// Don't set signature header
				req.Header.Set(HeaderPublicKey, "test")
				req.Header.Set(HeaderTimestamp, "123")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "missing X-Signature header",
		},
		{
			name: "MissingPublicKeyHeader",
			setupHeaders: func(req *http.Request) {
				req.Header.Set(HeaderSignature, "test")
				req.Header.Set(HeaderTimestamp, "123")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "missing X-Public-Key header",
		},
		{
			name: "MissingTimestampHeader",
			setupHeaders: func(req *http.Request) {
				req.Header.Set(HeaderSignature, "test")
				req.Header.Set(HeaderPublicKey, "test")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "missing X-Timestamp header",
		},
		{
			name: "InvalidTimestampFormat",
			setupHeaders: func(req *http.Request) {
				// Use a 32-byte dummy public key (required length for ed25519)
				dummyKey := make([]byte, 32)
				req.Header.Set(HeaderSignature, "dGVzdA==")
				req.Header.Set(HeaderPublicKey, base64.StdEncoding.EncodeToString(dummyKey))
				req.Header.Set(HeaderTimestamp, "not-a-number")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid timestamp format",
		},
		{
			name: "InvalidBase64Signature",
			setupHeaders: func(req *http.Request) {
				req.Header.Set(HeaderSignature, "not-base64!")
				req.Header.Set(HeaderPublicKey, "dGVzdA==")
				req.Header.Set(HeaderTimestamp, "123")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid signature",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			tc.setupHeaders(req)

			_, appErr := srv.verifyManagementRequest(req)
			require.NotNil(t, appErr, "Should return error")
			assert.Equal(t, tc.expectedStatus, appErr.Code)
			assert.Contains(t, appErr.Message, tc.expectedError)
		})
	}
}
