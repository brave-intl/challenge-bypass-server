package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/brave-intl/bat-go/libs/middleware"
	"github.com/go-chi/chi"
	chiware "github.com/go-chi/chi/middleware"
	"github.com/go-chi/httplog"
	"github.com/jmoiron/sqlx"
	"github.com/pressly/lg"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var (
	// Version - the version?
	Version        = "dev"
	maxRequestSize = int64(1024 * 1024) // 1MiB

	// ErrNoSecretKey - configuration error, no secret key
	ErrNoSecretKey = errors.New("server config does not contain a key")
	// ErrRequestTooLarge - processing error, request is too big
	ErrRequestTooLarge = errors.New("request too large to process")
	// ErrUnrecognizedRequest - processing error, request unrecognized
	ErrUnrecognizedRequest = errors.New("received unrecognized request type")
)

// init - Register Metrics for Server
func init() {
	// DB
	prometheus.MustRegister(fetchIssuerCounter)
	prometheus.MustRegister(createIssuerCounter)
	prometheus.MustRegister(redeemTokenCounter)
	prometheus.MustRegister(fetchRedemptionCounter)
	// DB latency
	prometheus.MustRegister(fetchIssuerByTypeDBDuration)
	prometheus.MustRegister(createIssuerDBDuration)
	prometheus.MustRegister(createRedemptionDBDuration)
	prometheus.MustRegister(fetchRedemptionDBDuration)
}

// Server - base server type
type Server struct {
	ListenPort   int            `json:"listen_port,omitempty"`
	MaxTokens    int            `json:"max_tokens,omitempty"`
	DBConfigPath string         `json:"db_config_path"`
	Logger       *logrus.Logger `json:",omitempty"`
	dynamo       *dynamodb.DynamoDB
	dbConfig     DBConfig
	db           *sqlx.DB

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

	// Heroku style
	if connectionURI := os.Getenv("DATABASE_URL"); connectionURI != "" {
		conf.ConnectionURI = os.Getenv("DATABASE_URL")
	}

	if dynamodbEndpoint := os.Getenv("DYNAMODB_ENDPOINT"); dynamodbEndpoint != "" {
		conf.DynamodbEndpoint = os.Getenv("DYNAMODB_ENDPOINT")
	}

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
		if cacheDurationSecs := os.Getenv("CACHE_DURATION_SECS"); cacheEnabled != "" {
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
func SetupLogger(ctx context.Context) (context.Context, *logrus.Logger) {
	logger := logrus.New()

	if os.Getenv("ENV") == "production" {
		logger.SetLevel(logrus.WarnLevel)
	}

	// Redirect output from the standard logging package "log"
	lg.RedirectStdlogOutput(logger)
	lg.DefaultLogger = logger
	ctx = lg.WithLoggerContext(ctx, logger)
	return ctx, logger
}

func (c *Server) setupRouter(ctx context.Context, logger *logrus.Logger) (context.Context, *chi.Mux) {
	r := chi.NewRouter()
	r.Use(chiware.RequestID)
	r.Use(chiware.Heartbeat("/"))
	r.Use(chiware.Timeout(60 * time.Second))
	r.Use(middleware.BearerToken)
	// Also handles panic recovery
	chiLogger := httplog.NewLogger("cbp-request-logs", httplog.Options{
		JSON: true,
	})
	r.Use(httplog.RequestLogger(chiLogger))

	c.Logger = logger

	// kick rotate v3 issuers on start
	if err := c.rotateIssuersV3(); err != nil {
		panic(err)
	}

	r.Mount("/v1/blindedToken", c.tokenRouterV1())
	r.Mount("/v1/issuer", c.issuerRouterV1())

	r.Mount("/v2/blindedToken", c.tokenRouterV2())
	r.Mount("/v2/issuer", c.issuerRouterV2())
	r.Get("/metrics", middleware.Metrics())

	// time aware token router
	r.Mount("/v3/blindedToken", c.tokenRouterV3())
	r.Mount("/v3/issuer", c.issuerRouterV3())

	return ctx, r
}

// ListenAndServe listen to ports and mount handlers
func (c *Server) ListenAndServe(ctx context.Context, logger *logrus.Logger) error {
	addr := fmt.Sprintf(":%d", c.ListenPort)
	srv := http.Server{Addr: addr, Handler: chi.ServerBaseContext(c.setupRouter(ctx, logger))}
	return srv.ListenAndServe()
}
