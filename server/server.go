package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/go-chi/chi"
	chiware "github.com/go-chi/chi/middleware"
	"github.com/pressly/lg"
	"github.com/sirupsen/logrus"
)

var (
	Version        = "dev"
	maxRequestSize = int64(20 * 1024) // ~10kB is expected size for 100*base64([64]byte) + ~framing

	ErrNoSecretKey         = errors.New("server config does not contain a key")
	ErrRequestTooLarge     = errors.New("request too large to process")
	ErrUnrecognizedRequest = errors.New("received unrecognized request type")
)

type Server struct {
	ListenPort   int    `json:"listen_port,omitempty"`
	MaxTokens    int    `json:"max_tokens,omitempty"`
	DbConfigPath string `json:"db_config_path"`

	dbConfig DbConfig
	db       *sql.DB
	caches   map[string]CacheInterface
}

var DefaultServer = &Server{
	ListenPort: 2416,
}

func LoadConfigFile(filePath string) (Server, error) {
	conf := *DefaultServer
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return conf, err
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		return conf, err
	}
	return conf, nil
}

var (
	ErrEmptyDbConfigPath = errors.New("no db config path specified")
)

func (c *Server) InitDbConfig() error {
	conf := DbConfig{}

	if envConfig := os.Getenv("DBCONFIG"); envConfig != "" {
		data := []byte(envConfig)
		err := json.Unmarshal(data, &conf)
		if err != nil {
			return err
		}

		// Heroku style
		if connectionURI := os.Getenv("DATABASE_URL"); connectionURI != "" {
			conf.ConnectionURI = os.Getenv("DATABASE_URL")
		}
	} else {
		if c.DbConfigPath == "" {
			return ErrEmptyDbConfigPath
		}

		data, err := ioutil.ReadFile(c.DbConfigPath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(data, &conf)
		if err != nil {
			return err
		}
	}

	c.LoadDbConfig(conf)

	return nil
}

func SetupLogger(ctx context.Context) (context.Context, *logrus.Logger) {
	logger := logrus.New()

	//logger.Formatter = &logrus.JSONFormatter{}

	// Redirect output from the standard logging package "log"
	lg.RedirectStdlogOutput(logger)
	lg.DefaultLogger = logger
	ctx = lg.WithLoggerContext(ctx, logger)
	return ctx, logger
}

func (c *Server) setupRouter(ctx context.Context, logger *logrus.Logger) (context.Context, *chi.Mux) {
	c.initDb()

	//govalidator.SetFieldsRequiredByDefault(true)

	r := chi.NewRouter()
	r.Use(chiware.RequestID)
	r.Use(chiware.Heartbeat("/"))
	r.Use(chiware.Timeout(60 * time.Second))
	r.Use(middleware.BearerToken)
	if logger != nil {
		// Also handles panic recovery
		r.Use(middleware.RequestLogger(logger))
	}

	r.Mount("/v1/blindedToken", c.tokenRouter())
	r.Mount("/v1/issuer", c.issuerRouter())
	r.Get("/metrics", middleware.Metrics())

	return ctx, r
}

func (c *Server) ListenAndServe(ctx context.Context, logger *logrus.Logger) error {
	addr := fmt.Sprintf(":%d", c.ListenPort)
	srv := http.Server{Addr: addr, Handler: chi.ServerBaseContext(c.setupRouter(ctx, logger))}
	return srv.ListenAndServe()
}
