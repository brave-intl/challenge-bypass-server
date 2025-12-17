package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// Chain takes middlewares and applies them in reverse order
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	// Apply middlewares in reverse order (last middleware is outermost)
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// RequestIDMiddleware adds a request ID to the context and response headers
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		ctx := context.WithValue(r.Context(), "requestID", requestID)
		// Add logger to context
		if logger, ok := r.Context().Value("logger").(*slog.Logger); ok {
			ctx = context.WithValue(ctx, "logger", logger)
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TimeoutMiddleware adds a timeout to the request context
func TimeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// DebuggingMiddleware logs the request details for debugging
func DebuggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log information about the request
		bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestSize))
		if err != nil {
			fmt.Printf("Error reading body: %v\n", err)
		}
		// Restore the body
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		fmt.Printf("Request path: %s, method: %s, content-type: %s, body length: %d\n",
			r.URL.Path, r.Method, r.Header.Get("Content-Type"), len(bodyBytes))
		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs request information
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.status = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// LoggingMiddleware logs HTTP requests
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			// Skip logging for certain paths
			if r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}
			rw := &responseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			// Add logger to context
			ctx := context.WithValue(r.Context(), "logger", logger)
			r = r.WithContext(ctx)

			next.ServeHTTP(rw, r)
			duration := time.Since(start)
			requestID, _ := r.Context().Value("requestID").(string)
			logger.Info("request completed",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rw.status),
				slog.Int("size", rw.size),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.String("request_id", requestID),
				slog.Duration("duration", duration),
			)
		})
	}
}

type bearerTokenKey struct{}

var (
	// TokenList is the list of tokens that are accepted as valid
	TokenList = strings.Split(os.Getenv("TOKEN_LIST"), ",")
)

// BearerToken is a middleware that adds the bearer token included in a request's headers to context
func BearerTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		bearer := r.Header.Get("Authorization")

		if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
			token = bearer[7:]
		}
		ctx := context.WithValue(r.Context(), bearerTokenKey{}, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isSimpleTokenValid(list []string, token string) bool {
	if token == "" {
		return false
	}
	for _, validToken := range list {
		// NOTE token length information is leaked even with subtle.ConstantTimeCompare
		if subtle.ConstantTimeCompare([]byte(validToken), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

func isSimpleTokenInContext(ctx context.Context) bool {
	token, ok := ctx.Value(bearerTokenKey{}).(string)
	if !ok || !isSimpleTokenValid(TokenList, token) {
		return false
	}
	return true
}

// SimpleTokenAuthorizedOnly is a middleware that restricts access to requests with a valid bearer token via context
// NOTE the valid token is populated via BearerToken
func SimpleTokenAuthorizedOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSimpleTokenInContext(r.Context()) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// StripTrailingSlash makes routes with and without a trailing slash work the same.
func StripTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			// Create a new URL with the trailing slash removed
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		}
		next.ServeHTTP(w, r)
	})
}
