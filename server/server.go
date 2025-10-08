// server.go - with consolidated routing
package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
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
	metrics.MustRegisterIfNotRegistered(
		prometheus.DefaultRegisterer,
		// DB
		fetchIssuerTotal,
		createIssuerTotal,
		redeemTokenTotal,
		fetchRedemptionTotal,
		// DB latency
		fetchIssuerByTypeDBDuration,
		createIssuerDBDuration,
		createRedemptionDBDuration,
		fetchRedemptionDBDuration,
		// API Calls
		v1BlindedTokenCallTotal,
		v1IssuerCallTotal,
		v2BlindedTokenCallTotal,
		v2IssuerCallTotal,
		v3BlindedTokenCallTotal,
		v3IssuerCallTotal,
	)
}

// Server - base server type
type Server struct {
	ListenPort   int          `json:"listen_port,omitempty"`
	MaxTokens    int          `json:"max_tokens,omitempty"`
	DBConfigPath string       `json:"db_config_path"`
	Logger       *slog.Logger `json:",omitempty"`
	dynamo       *dynamodb.DynamoDB
	dbConfig     DBConfig
	db           *sql.DB // Database writer instance
	dbr          *sql.DB // Database reader instance

	caches map[string]CacheInterface
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

// InitDBConfig reads os environment and update conf
func (c *Server) InitDBConfig() error {
	conf := DBConfig{
		DefaultDaysBeforeExpiry: 7,
		DefaultIssuerValidDays:  30,
		MaxConnection:           100,
	}

	conf.ConnectionURI = os.Getenv("DATABASE_URL")
	conf.ConnectionURIReader = os.Getenv("DATABASE_READER_URL")
	conf.DynamodbEndpoint = os.Getenv("DYNAMODB_ENDPOINT")

	if maxConnection := os.Getenv("MAX_DB_CONNECTION"); maxConnection != "" {
		if count, err := strconv.Atoi(maxConnection); err == nil {
			conf.MaxConnection = count
		}
	}

	if defaultDaysBeforeExpiry := os.Getenv("DEFAULT_DAYS_BEFORE_EXPIRY"); defaultDaysBeforeExpiry != "" {
		if count, err := strconv.Atoi(defaultDaysBeforeExpiry); err == nil {
			conf.DefaultDaysBeforeExpiry = count
		}
	}

	if defaultIssuerValidDays := os.Getenv("DEFAULT_ISSUER_VALID_DAYS"); defaultIssuerValidDays != "" {
		if count, err := strconv.Atoi(defaultIssuerValidDays); err == nil {
			conf.DefaultIssuerValidDays = count
		}
	}

	if cacheEnabled := os.Getenv("CACHE_ENABLED"); cacheEnabled == "true" {
		cachingConfig := CachingConfig{
			Enabled:       true,
			ExpirationSec: 10,
		}
		if cacheDurationSecs := os.Getenv("CACHE_DURATION_SECS"); cacheDurationSecs != "" {
			if secs, err := strconv.Atoi(cacheDurationSecs); err == nil {
				cachingConfig.ExpirationSec = secs
			}
		}
		conf.CachingConfig = cachingConfig
	}

	c.LoadDBConfig(conf)

	return nil
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

// setupRouter sets up all routes for the server
func (c *Server) setupRouter(logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	c.Logger = logger

	// Kick rotate v3 issuers on start
	if err := c.rotateIssuersV3(); err != nil {
		// @TODO: Alert here once merged
		panic(err)
	}

	// Helper to register authenticated routes
	registerAuth := func(pattern string, handler func(http.ResponseWriter, *http.Request) *AppError) {
		mux.Handle(pattern, c.withAuth(AppHandler(handler)))
	}

	// Helper to register public routes with base middleware
	registerPublic := func(pattern string, handler http.Handler) {
		mux.Handle(pattern, c.withBase(handler))
	}

	// Root health check endpoint
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("."))
	})

	// =========== V1 API Routes ===========
	// V1 Token Routes
	registerAuth("GET /v1/blindedToken/{type}", c.blindedTokenIssuerHandler)
	registerAuth("POST /v1/blindedToken/{type}", c.blindedTokenIssuerHandler)
	registerAuth("POST /v1/blindedToken/{type}/redemption", c.blindedTokenRedeemHandler)
	registerAuth("GET /v1/blindedToken/{id}/redemption/{tokenId}", c.blindedTokenRedemptionHandler)
	registerAuth("POST /v1/blindedToken/bulk/redemption", c.blindedTokenBulkRedeemHandler)

	// V1 Issuer Routes
	registerAuth("GET /v1/issuer/{type}", c.issuerGetHandlerV1)
	registerAuth("POST /v1/issuer", c.issuerCreateHandlerV1)
	registerAuth("GET /v1/issuer", c.issuerGetAllHandler)

	// =========== V2 API Routes ===========
	// V2 Token Routes
	registerAuth("GET /v2/blindedToken/{type}", c.BlindedTokenIssuerHandlerV2)
	registerAuth("POST /v2/blindedToken/{type}", c.BlindedTokenIssuerHandlerV2)

	// V2 Issuer Routes
	registerAuth("GET /v2/issuer/{type}", c.issuerHandlerV2)
	registerAuth("POST /v2/issuer", c.issuerCreateHandlerV2)

	// =========== V3 API Routes ===========
	// V3 Token Routes
	registerAuth("POST /v3/blindedToken/{type}/redemption", c.blindedTokenRedeemHandlerV3)

	// V3 Issuer Routes
	registerAuth("GET /v3/issuer/{type}", c.issuerHandlerV3)
	registerAuth("POST /v3/issuer", c.issuerV3CreateHandler)

	// Metrics endpoint
	registerPublic("GET /metrics", promhttp.Handler())

	// Wrap the entire mux with StripTrailingSlash middleware
	return StripTrailingSlash(mux)
}

func (c *Server) withBase(h http.Handler) http.Handler {
	return Chain(h,
		RequestIDMiddleware,
		TimeoutMiddleware(60*time.Second),
		BearerTokenMiddleware,
		LoggingMiddleware(c.Logger),
	)
}

func (c *Server) withAuth(h http.Handler) http.Handler {
	// Start with base middleware chain
	h = c.withBase(h)

	// Add auth middleware in production
	if os.Getenv("ENV") == "production" {
		h = SimpleTokenAuthorizedOnly(h)
	}

	return h
}

// ListenAndServe listen to ports and mount handlers
func (c *Server) ListenAndServe(logger *slog.Logger) error {
	router := c.setupRouter(logger)

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
