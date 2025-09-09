// server.go - with consolidated routing
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	maxRequestSize = int64(1024 * 1024) // 1MiB
	// ErrNoSecretKey - configuration error, no secret key
	ErrNoSecretKey = errors.New("server config does not contain a key")
	// ErrRequestTooLarge - processing error, request is too big
	ErrRequestTooLarge = errors.New("request too large to process")
	// ErrUnrecognizedRequest - processing error, request unrecognized
	ErrUnrecognizedRequest = errors.New("received unrecognized request type")

	v1BlindedTokenCallTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_api_v1_blinded_token_total",
			Help: "Number of calls to V1 blinded token HTTP endpoint",
		},
		[]string{"action"},
	)
	v1IssuerCallTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_api_v1_issuer_total",
			Help: "Number of calls to V1 issuer HTTP endpoint",
		},
		[]string{"action"},
	)
	v2BlindedTokenCallTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_api_v2_blinded_token_total",
			Help: "Number of calls to V2 blinded token HTTP endpoint",
		},
		[]string{"action"},
	)
	v2IssuerCallTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_api_v2_issuer_total",
			Help: "Number of calls to V2 issuer HTTP endpoint",
		},
		[]string{"action"},
	)
	v3BlindedTokenCallTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_api_v3_blinded_token_total",
			Help: "Number of calls to V3 blinded token HTTP endpoint",
		},
		[]string{"action"},
	)
	v3IssuerCallTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_api_v3_issuer_total",
			Help: "Number of calls to V3 issuer HTTP endpoint",
		},
		[]string{"action"},
	)
)

// init - Register Metrics for Server
func init() {
	// DB
	prometheus.MustRegister(fetchIssuerTotal)
	prometheus.MustRegister(createIssuerTotal)
	prometheus.MustRegister(redeemTokenTotal)
	prometheus.MustRegister(fetchRedemptionTotal)
	// DB latency
	prometheus.MustRegister(fetchIssuerByTypeDBDuration)
	prometheus.MustRegister(createIssuerDBDuration)
	prometheus.MustRegister(createRedemptionDBDuration)
	prometheus.MustRegister(fetchRedemptionDBDuration)
	// API Calls
	prometheus.MustRegister(v1BlindedTokenCallTotal)
	prometheus.MustRegister(v1IssuerCallTotal)
	prometheus.MustRegister(v2BlindedTokenCallTotal)
	prometheus.MustRegister(v2IssuerCallTotal)
	prometheus.MustRegister(v3BlindedTokenCallTotal)
	prometheus.MustRegister(v3IssuerCallTotal)
}

// Server - base server type
type Server struct {
	ListenPort   int          `json:"listen_port,omitempty"`
	MaxTokens    int          `json:"max_tokens,omitempty"`
	DBConfigPath string       `json:"db_config_path"`
	Logger       *slog.Logger `json:",omitempty"`
	dynamo       *dynamodb.DynamoDB
	dbConfig     DBConfig
	db           *sqlx.DB
	caches       map[string]CacheInterface
	router       *CustomServeMux
}

// DefaultServer on port
var DefaultServer = &Server{
	ListenPort: 2416,
}

// LoadConfigFile loads a file into conf and returns
func LoadConfigFile(filePath string) (Server, error) {
	conf := *DefaultServer
	data, err := os.ReadFile(filePath)
	if err != nil {
		return conf, err
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		return conf, err
	}
	return conf, nil
}

// SetupLogger creates a logger to use
func SetupLogger(
	version,
	buildTime,
	commit string,
) *slog.Logger {
	// Simplify logs during local development
	env := os.Getenv("ENV")
	var level slog.Level
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "INFO":
		level = slog.LevelInfo
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelWarn
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})).With(
		slog.String("app", "challenge-bypass"),
		slog.String("version", version),
		slog.String("buildTime", buildTime),
		slog.String("commit", commit),
		slog.String("version", version),
		slog.String("env", env),
	)
	return logger
}

// CustomServeMux is a custom HTTP router that supports URL parameters
type CustomServeMux struct {
	routes     map[string]http.Handler
	patterns   []*regexp.Regexp
	handlers   []http.Handler
	middleware []func(http.Handler) http.Handler
}

// NewCustomServeMux creates a new custom HTTP router
func NewCustomServeMux() *CustomServeMux {
	return &CustomServeMux{
		routes:     make(map[string]http.Handler),
		patterns:   make([]*regexp.Regexp, 0),
		handlers:   make([]http.Handler, 0),
		middleware: make([]func(http.Handler) http.Handler, 0),
	}
}

// Use adds middleware to the router
func (m *CustomServeMux) Use(middleware ...func(http.Handler) http.Handler) {
	m.middleware = append(m.middleware, middleware...)
}

// Handle registers a handler for a specific path
func (m *CustomServeMux) Handle(pattern string, handler http.Handler) {
	// If it's a static route without parameters
	if !strings.Contains(pattern, "{") && !strings.Contains(pattern, "}") {
		// Apply all middleware to the handler
		for i := len(m.middleware) - 1; i >= 0; i-- {
			handler = m.middleware[i](handler)
		}
		m.routes[pattern] = handler
		return
	}
	// Convert Chi-style URL params to regexp
	// Convert {param} to (?P<param>[^/]+)
	regexPattern := pattern
	regexPattern = strings.Replace(regexPattern, "/", "\\/", -1)
	re := regexp.MustCompile(`\{([^}]+)\}`)
	regexPattern = re.ReplaceAllString(regexPattern, `(?P<$1>[^/]+)`)
	regexPattern = "^" + regexPattern + "$"
	// Compile the regexp pattern
	r, err := regexp.Compile(regexPattern)
	if err != nil {
		panic(err)
	}
	// Apply all middleware to the handler
	for i := len(m.middleware) - 1; i >= 0; i-- {
		handler = m.middleware[i](handler)
	}
	// Store the pattern and handler
	m.patterns = append(m.patterns, r)
	m.handlers = append(m.handlers, handler)
}

// HandleFunc registers a handler function for a specific path
func (m *CustomServeMux) HandleFunc(pattern string, handlerFunc func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(handlerFunc))
}

// ServeHTTP handles HTTP requests
func (m *CustomServeMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check for exact routes first
	if handler, ok := m.routes[r.URL.Path]; ok {
		handler.ServeHTTP(w, r)
		return
	}
	// Check for pattern matches
	for i, pattern := range m.patterns {
		matches := pattern.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			// Create a context with URL parameters
			ctx := r.Context()
			// Add params to the context
			for j, name := range pattern.SubexpNames() {
				if j != 0 && name != "" {
					ctx = context.WithValue(ctx, name, matches[j])
				}
			}
			// Update the request with the new context
			r = r.WithContext(ctx)
			// Call the handler
			m.handlers[i].ServeHTTP(w, r)
			return
		}
	}
	// If no route matches, return 404
	http.NotFound(w, r)
}

// URLParam retrieves the URL parameter from the request context
func URLParam(r *http.Request, key string) string {
	if value, ok := r.Context().Value(key).(string); ok {
		return value
	}
	return ""
}

// setupRouter sets up all routes for the server
func (c *Server) setupRouter(logger *slog.Logger) *CustomServeMux {
	r := NewCustomServeMux()
	c.Logger = logger
	// Setup common middleware
	r.Use(
		RequestIDMiddleware,
		TimeoutMiddleware(60*time.Second),
		BearerTokenMiddleware,
		LoggingMiddleware(logger),
	)
	// kick rotate v3 issuers on start
	if err := c.rotateIssuersV3(); err != nil {
		panic(err)
	}
	// Get the auth middleware based on environment
	var authMiddleware func(http.Handler) http.Handler
	if os.Getenv("ENV") == "production" {
		authMiddleware = SimpleTokenAuthorizedOnly
	} else {
		// No-op middleware for non-production
		authMiddleware = func(next http.Handler) http.Handler {
			return next
		}
	}
	// Replace the heartbeat middleware with a simple route
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("."))
	})

	// =========== V1 API Routes ===========
	// V1 Token Routes
	r.Handle(
		"/v1/blindedToken/{type}",
		authMiddleware(AppHandler(c.blindedTokenIssuerHandler)),
	)
	r.Handle(
		"/v1/blindedToken/{type}/redemption/",
		authMiddleware(AppHandler(c.blindedTokenRedeemHandler)),
	)
	r.Handle(
		"/v1/blindedToken/{id}/redemption/{tokenId}",
		authMiddleware(AppHandler(c.blindedTokenRedemptionHandler)),
	)
	r.Handle(
		"/v1/blindedToken/bulk/redemption/",
		authMiddleware(AppHandler(c.blindedTokenBulkRedeemHandler)),
	)

	// V1 Issuer Routes - Modified to be method-specific
	// GET /v1/issuer/{type} - Get a specific issuer
	r.Handle("/v1/issuer/{type}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			authMiddleware(AppHandler(c.issuerGetHandlerV1)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// POST /v1/issuer - Create a new issuer
	r.Handle("/v1/issuer/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			authMiddleware(AppHandler(c.issuerCreateHandlerV1)).ServeHTTP(w, r)
		} else if r.Method == http.MethodGet {
			authMiddleware(AppHandler(c.issuerGetAllHandler)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// Handle bare URL with no trailing slash for POST requests
	r.Handle("/v1/issuer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			authMiddleware(AppHandler(c.issuerCreateHandlerV1)).ServeHTTP(w, r)
		} else if r.Method == http.MethodGet {
			authMiddleware(AppHandler(c.issuerGetAllHandler)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// =========== V2 API Routes ===========
	// V2 Token Routes
	r.Handle("/v2/blindedToken/{type}", authMiddleware(AppHandler(c.BlindedTokenIssuerHandlerV2)))

	// V2 Issuer Routes - Also method-specific
	// GET /v2/issuer/{type} - Get a specific issuer
	r.Handle("/v2/issuer/{type}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			authMiddleware(AppHandler(c.issuerHandlerV2)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// POST /v2/issuer - Create a new issuer
	r.Handle("/v2/issuer/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			authMiddleware(AppHandler(c.issuerCreateHandlerV2)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// Handle bare URL with no trailing slash for POST requests
	r.Handle("/v2/issuer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			authMiddleware(AppHandler(c.issuerCreateHandlerV2)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// =========== V3 API Routes ===========
	// V3 Token Routes
	r.Handle(
		"/v3/blindedToken/{type}/redemption/",
		authMiddleware(AppHandler(c.blindedTokenRedeemHandlerV3)),
	)

	// V3 Issuer Routes - Also method-specific
	// GET /v3/issuer/{type} - Get a specific issuer
	r.Handle("/v3/issuer/{type}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			authMiddleware(AppHandler(c.issuerHandlerV3)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// POST /v3/issuer - Create a new issuer
	r.Handle("/v3/issuer/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			authMiddleware(AppHandler(c.issuerV3CreateHandler)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// Handle bare URL with no trailing slash for POST requests
	r.Handle("/v3/issuer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			authMiddleware(AppHandler(c.issuerV3CreateHandler)).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// Metrics endpoint
	r.Handle("/metrics", promhttp.Handler().(http.HandlerFunc))
	return r
}

// ListenAndServe listen to ports and mount handlers
func (c *Server) ListenAndServe(logger *slog.Logger) error {
	router := c.setupRouter(logger)
	c.router = router
	ServeMetrics()
	return http.ListenAndServe(fmt.Sprintf(":%d", c.ListenPort), router)
}

// ServeMetrics exposes the metrics collection endpoint on :9090
func ServeMetrics() {
	// Run metrics on 9090 for collection
	r := http.NewServeMux()
	r.Handle("/metrics", promhttp.Handler().(http.HandlerFunc))
	go http.ListenAndServe(":9090", r)
}
