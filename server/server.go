// server.go - with consolidated routing
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	"github.com/go-chi/chi/v5"
	chiware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v3"
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
	cronTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_cron_total",
			Help: "Count of cron runs and their outcomes",
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
		// Cron
		cronTotal,
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

	caches *CacheCollection
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
	ctx context.Context,
	version,
	buildTime,
	commit string,
) (context.Context, *slog.Logger) {
	// Simplify logs during local development
	env := os.Getenv("ENV")
	logFormat := httplog.SchemaECS.Concise(env == "local")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:       slog.LevelWarn,
		ReplaceAttr: logFormat.ReplaceAttr,
	})).With(
		slog.String("app", "challenge-bypass"),
		slog.String("version", version),
		slog.String("buildTime", buildTime),
		slog.String("commit", commit),
		slog.String("version", version),
		slog.String("env", env),
	)
	return ctx, logger
}

// setupRouter sets up all routes for the server
func (c *Server) setupRouter(ctx context.Context, logger *slog.Logger) (context.Context, http.Handler) {
	r := chi.NewRouter()
	c.Logger = logger

	// Kick rotate v3 issuers on start
	if err := c.rotateIssuersV3(); err != nil {
		// @TODO: Alert here once merged
		panic(err)
	}

	// Root health check endpoint
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("."))
	})

	r.Group(func(r chi.Router) {
		r.Use(chiware.RequestID)
		r.Use(chiware.Timeout(60 * time.Second))
		r.Use(BearerTokenMiddleware)

		chiLogger := httplog.RequestLogger(logger, &httplog.Options{
			RecoverPanics: true,
			Schema:        httplog.SchemaECS,
			Skip: func(req *http.Request, respStatus int) bool {
				return req.URL.Path == "/metrics"
			},
		})
		r.Use(chiLogger)

		// Metrics endpoint
		r.Method("GET", "/metrics", promhttp.Handler())

		// Authenticated Routes
		r.Group(func(r chi.Router) {
			if os.Getenv("ENV") == "production" {
				r.Use(SimpleTokenAuthorizedOnly)
			}

			// =========== V1 API Routes ===========
			// V1 Token Routes
			r.Method("GET", "/v1/blindedToken/{type}", AppHandler(c.blindedTokenIssuerHandler))
			r.Method("POST", "/v1/blindedToken/{type}", AppHandler(c.blindedTokenIssuerHandler))
			r.Method("POST", "/v1/blindedToken/{type}/redemption", AppHandler(c.blindedTokenRedeemHandler))
			r.Method("GET", "/v1/blindedToken/{id}/redemption/{tokenId}", AppHandler(c.blindedTokenRedemptionHandler))
			r.Method("POST", "/v1/blindedToken/bulk/redemption", AppHandler(c.blindedTokenBulkRedeemHandler))

			// V1 Issuer Routes
			r.Method("GET", "/v1/issuer/{type}", AppHandler(c.issuerGetHandlerV1))
			r.Method("POST", "/v1/issuer", AppHandler(c.issuerCreateHandlerV1))
			r.Method("GET", "/v1/issuer", AppHandler(c.issuerGetAllHandler))

			// =========== V2 API Routes ===========
			// V2 Token Routes
			r.Method("GET", "/v2/blindedToken/{type}", AppHandler(c.BlindedTokenIssuerHandlerV2))
			r.Method("POST", "/v2/blindedToken/{type}", AppHandler(c.BlindedTokenIssuerHandlerV2))

			// V2 Issuer Routes
			r.Method("GET", "/v2/issuer/{type}", AppHandler(c.issuerHandlerV2))
			r.Method("POST", "/v2/issuer", AppHandler(c.issuerCreateHandlerV2))

			// =========== V3 API Routes ===========
			// V3 Token Routes
			r.Method("POST", "/v3/blindedToken/{type}/redemption", AppHandler(c.blindedTokenRedeemHandlerV3))

			// V3 Issuer Routes
			r.Method("GET", "/v3/issuer/{type}", AppHandler(c.issuerHandlerV3))
			r.Method("POST", "/v3/issuer", AppHandler(c.issuerV3CreateHandler))
		})
	})

	// Wrap the entire mux with StripTrailingSlash middleware
	return ctx, chiware.StripSlashes(r)
}

// ListenAndServe listen to ports and mount handlers
func (c *Server) ListenAndServe(ctx context.Context, logger *slog.Logger) error {
	_, router := c.setupRouter(ctx, logger)

	ServeMetrics()

	return http.ListenAndServe(fmt.Sprintf(":%d", c.ListenPort), router)
}

// ServeMetrics exposes the metrics collection endpoint on :9090
func ServeMetrics() {
	// Run metrics on 9090 for collection
	r := chi.NewRouter()
	r.Method("GET", "/metrics", promhttp.Handler())
	go http.ListenAndServe(":9090", r)
}
