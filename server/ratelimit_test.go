package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(60, 1*time.Minute)
	assert.NotNil(t, rl)
	assert.Equal(t, 60, rl.maxReqs)
	assert.Equal(t, 1*time.Minute, rl.window)
}

func TestRateLimiter_Allow_UnderLimit(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Minute)

	// Should allow first 5 requests
	for i := 0; i < 5; i++ {
		allowed := rl.Allow("192.168.1.1")
		assert.True(t, allowed, "Request %d should be allowed", i+1)
	}
}

func TestRateLimiter_Allow_OverLimit(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Minute)

	// Use up the limit
	for i := 0; i < 5; i++ {
		rl.Allow("192.168.1.1")
	}

	// Next request should be denied
	allowed := rl.Allow("192.168.1.1")
	assert.False(t, allowed, "Request over limit should be denied")
}

func TestRateLimiter_Allow_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Minute)

	// Use up limit for first IP
	for i := 0; i < 5; i++ {
		rl.Allow("192.168.1.1")
	}

	// Second IP should still be allowed
	allowed := rl.Allow("192.168.1.2")
	assert.True(t, allowed, "Different IP should have separate limit")
}

func TestRateLimiter_Allow_SlidingWindow(t *testing.T) {
	// Use a very short window for testing
	rl := NewRateLimiter(3, 100*time.Millisecond)

	// Use up the limit
	for i := 0; i < 3; i++ {
		allowed := rl.Allow("192.168.1.1")
		require.True(t, allowed)
	}

	// Should be denied immediately
	allowed := rl.Allow("192.168.1.1")
	assert.False(t, allowed)

	// Wait for window to pass
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	allowed = rl.Allow("192.168.1.1")
	assert.True(t, allowed, "Request should be allowed after window expires")
}

func TestRateLimiter_CleanupOldLimiters(t *testing.T) {
	// Use short window and cleanup interval for testing
	rl := NewRateLimiter(5, 50*time.Millisecond)

	// Make requests from multiple IPs
	rl.Allow("192.168.1.1")
	rl.Allow("192.168.1.2")
	rl.Allow("192.168.1.3")

	// Should have 3 limiters
	rl.mu.RLock()
	initialCount := len(rl.limiters)
	rl.mu.RUnlock()
	assert.Equal(t, 3, initialCount)

	// Start cleanup with short interval
	rl.CleanupOldLimiters(80 * time.Millisecond)

	// Wait for requests to age beyond 2*window (100ms) + cleanup to run
	time.Sleep(250 * time.Millisecond)

	// Limiters should be cleaned up
	rl.mu.RLock()
	finalCount := len(rl.limiters)
	rl.mu.RUnlock()
	assert.Equal(t, 0, finalCount, "Old limiters should be cleaned up")
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	ip := getClientIP(req)
	assert.Equal(t, "192.168.1.1", ip)
}

func TestGetClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.2")

	ip := getClientIP(req)
	assert.Equal(t, "192.168.1.1", ip, "Should use first IP from X-Forwarded-For")
}

func TestGetClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-IP", "192.168.1.1")

	ip := getClientIP(req)
	assert.Equal(t, "192.168.1.1", ip, "Should use X-Real-IP")
}

func TestGetClientIP_XForwardedForPriority(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.1")
	req.Header.Set("X-Real-IP", "192.168.1.2")

	ip := getClientIP(req)
	assert.Equal(t, "192.168.1.1", ip, "X-Forwarded-For should take priority")
}

func TestRateLimitMiddleware_Allowed(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Minute)
	srv := &Server{}

	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := srv.RateLimitMiddleware(rl)
	wrappedHandler := middleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	assert.True(t, handlerCalled, "Handler should be called when under limit")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimitMiddleware_RateLimited(t *testing.T) {
	rl := NewRateLimiter(2, 1*time.Minute)
	srv := &Server{}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := srv.RateLimitMiddleware(rl)
	wrappedHandler := middleware(testHandler)

	// Use up the limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Next request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "Rate limit exceeded")
}
