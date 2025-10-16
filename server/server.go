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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/brave-intl/bat-go/libs/middleware"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	"github.com/go-chi/chi/v5"
	chiware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v3"
	"github.com/prometheus/client_golang/prometheus"
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

	caches map[string]Cache
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

	logFormat := httplog.SchemaECS.Concise(env == "local")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: logFormat.ReplaceAttr,
		Level:       level,
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

func (c *Server) setupRouter(ctx context.Context, logger *slog.Logger) (context.Context, *chi.Mux) {
	r := chi.NewRouter()
	r.Use(chiware.RequestID)
	r.Use(chiware.Heartbeat("/"))
	r.Use(chiware.Timeout(60 * time.Second))
	r.Use(middleware.BearerToken)
	chiLogger := httplog.RequestLogger(logger, &httplog.Options{
		RecoverPanics: true,
		Schema:        httplog.SchemaECS,
		Skip: func(req *http.Request, respStatus int) bool {
			return req.URL.Path == "/metrics"
		},
	})
	r.Use(chiLogger)

	c.Logger = logger

	// kick rotate v3 issuers on start
	if err := c.rotateIssuersV3(); err != nil {
		panic(err)
	}

	r.Mount("/v1/blindedToken", c.tokenRouterV1())
	r.Mount("/v1/issuer", c.issuerRouterV1())

	r.Mount("/v2/blindedToken", c.tokenRouterV2())
	r.Mount("/v2/issuer", c.issuerRouterV2())

	// time aware token router
	r.Mount("/v3/blindedToken", c.tokenRouterV3())
	r.Mount("/v3/issuer", c.issuerRouterV3())

	// Metrics for retroactive compatibility
	// @TODO: Remove  this once the service health check is transferred to th 9090
	// version
	r.Get("/metrics", middleware.Metrics())

	return ctx, r
}

// ListenAndServe listen to ports and mount handlers
func (c *Server) ListenAndServe(ctx context.Context, logger *slog.Logger) error {
	_, srv := c.setupRouter(ctx, logger)

	ServeMetrics()

	return http.ListenAndServe(fmt.Sprintf(":%d", c.ListenPort), srv)
}

// ServeMetrics exposes the metrics collection endpoint on :9090
func ServeMetrics() {
	// Run metrics on 9090 for collection
	r := chi.NewRouter()
	r.Get("/metrics", middleware.Metrics())
	go http.ListenAndServe(":9090", r)
}
