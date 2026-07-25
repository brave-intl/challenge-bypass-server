package server

import (
	"net/http"
	"sync"
	"time"
)

// ipRateLimiter tracks request times for a single IP using a sliding window
type ipRateLimiter struct {
	requests []time.Time
	mu       sync.Mutex
}

// RateLimiter manages rate limits for management API requests
type RateLimiter struct {
	limiters map[string]*ipRateLimiter
	mu       sync.RWMutex
	window   time.Duration // time window for rate limiting
	maxReqs  int           // maximum requests per window
}

// NewRateLimiter creates a new rate limiter with the specified limit
// requestsPerMinute: maximum requests allowed per minute per IP
// window: time window to track (typically 1 minute)
func NewRateLimiter(requestsPerMinute int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*ipRateLimiter),
		window:   window,
		maxReqs:  requestsPerMinute,
	}
}

// getLimiter returns the rate limiter for a given IP address
func (rl *RateLimiter) getLimiter(ip string) *ipRateLimiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = &ipRateLimiter{
			requests: make([]time.Time, 0, rl.maxReqs),
		}
		rl.limiters[ip] = limiter
	}

	return limiter
}

// Allow checks if a request from the given IP should be allowed
// Uses a sliding window algorithm
func (rl *RateLimiter) Allow(ip string) bool {
	limiter := rl.getLimiter(ip)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Remove requests outside the window
	valid := 0
	for i := range limiter.requests {
		if limiter.requests[i].After(cutoff) {
			limiter.requests[valid] = limiter.requests[i]
			valid++
		}
	}
	limiter.requests = limiter.requests[:valid]

	// Check if we're at the limit
	if len(limiter.requests) >= rl.maxReqs {
		return false
	}

	// Add this request
	limiter.requests = append(limiter.requests, now)
	return true
}

// CleanupOldLimiters periodically removes inactive limiters to prevent memory leaks
func (rl *RateLimiter) CleanupOldLimiters(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			rl.mu.Lock()
			now := time.Now()
			cutoff := now.Add(-rl.window * 2) // Remove if no requests for 2x window

			for ip, limiter := range rl.limiters {
				limiter.mu.Lock()
				if len(limiter.requests) == 0 ||
					(len(limiter.requests) > 0 && limiter.requests[len(limiter.requests)-1].Before(cutoff)) {
					delete(rl.limiters, ip)
				}
				limiter.mu.Unlock()
			}
			rl.mu.Unlock()
		}
	}()
}

// RateLimitMiddleware returns middleware that applies rate limiting per IP address
func (c *Server) RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract IP from request
			ip := getClientIP(r)

			// Check rate limit
			if !limiter.Allow(ip) {
				rateLimitExceededTotal.Inc()
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP address from the request
// It checks X-Forwarded-For and X-Real-IP headers first (for proxy setups)
// Falls back to RemoteAddr if headers are not present
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (comma-separated list, first is client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	// RemoteAddr is in format "IP:port", we only want the IP
	ip := r.RemoteAddr
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == ':' {
			return ip[:i]
		}
	}
	return ip
}
