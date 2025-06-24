package main

import (
	"context"
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"time"

	"github.com/brave-intl/bat-go/libs/logging"
	"github.com/brave-intl/bat-go/libs/middleware"
	"github.com/brave-intl/challenge-bypass-server/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	raven "github.com/getsentry/raven-go"
	"github.com/go-chi/chi"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Server setup
	var (
		configFile string
		err        error
		logLevel   zerolog.Level
	)

	serverCtx, logger := server.SetupLogger(context.Background())
	logLevel = zerolog.WarnLevel
	if os.Getenv("ENV") == "local" {
		logLevel = zerolog.TraceLevel
	}
	_, zeroLogger := logging.SetupLoggerWithLevel(serverCtx, logLevel)

	srv := *server.DefaultServer
	srv.Logger = logger

	flag.StringVar(&configFile, "config", "", "local config file for development (overrides cli options)")
	flag.StringVar(&srv.DBConfigPath, "db_config", "", "path to the json file with database configuration")
	flag.IntVar(&srv.ListenPort, "p", 2416, "port to listen on")
	flag.Parse()

	if configFile != "" {
		srv, err = server.LoadConfigFile(configFile)
		if err != nil {
			logger.Panic(err)
			return
		}
	}

	if port := os.Getenv("PORT"); port != "" {
		if portNumber, err := strconv.Atoi(port); err == nil {
			srv.ListenPort = portNumber
		}
	}

	err = srv.InitDBConfig()
	if err != nil {
		logger.Panic(err)
	}

	zeroLogger.Trace().Msg("Initializing persistence and cron jobs")

	// Initialize databases and cron tasks before the Kafka processors and server start
	srv.InitDB()
	srv.InitDynamo()
	// Run the cron job unless it's explicitly disabled.
	if os.Getenv("CRON_ENABLED") != "false" {
		srv.SetupCronTasks()
	}

	zeroLogger.Trace().Msg("Persistence and cron jobs initialized")

	// add profiling flag to enable profiling routes
	if os.Getenv("PPROF_ENABLE") != "" {
		zeroLogger.Trace().Msg("Enabling PPROF")
		var addr = ":6061"
		if os.Getenv("PPROF_PORT") != "" {
			addr = os.Getenv("PPROF_PORT")
		}

		// pprof attaches routes to default serve mux
		// host:6061/debug/pprof/
		go func() {
			log.Error().Err(http.ListenAndServe(addr, http.DefaultServeMux))
		}()
	}

	if os.Getenv("KAFKA_ENABLED") != "false" {
		r := chi.NewRouter()
		r.Get("/metrics", middleware.Metrics())
		go http.ListenAndServe(":9090", r)
		zeroLogger.Trace().Msg("Spawning Kafka goroutine")
		startKafka(srv, zeroLogger)
	}

	zeroLogger.Trace().Msg("Initializing API server")
	err = srv.ListenAndServe(serverCtx, logger)
	if err != nil {
		zeroLogger.Error().Err(err).Msg("Failed to initialize API server")
		raven.CaptureErrorAndWait(err, nil)
		logger.Panic(err)
		return
	}
}

func startKafka(srv server.Server, zeroLogger *zerolog.Logger) {
	ctx := context.Background()
	zeroLogger.Trace().Msg("Initializing Kafka consumers")
	err := kafka.StartConsumers(ctx, &srv, zeroLogger)

	if err != nil {
		zeroLogger.Error().Err(err).Msg("Failed to initialize Kafka consumers")
		// If err is something then start consumer again
		time.Sleep(10 * time.Second)
		startKafka(srv, zeroLogger)
	}
}
