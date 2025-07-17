package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"time"

	"github.com/brave-intl/challenge-bypass-server/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	raven "github.com/getsentry/raven-go"
)

func main() {
	// Server setup
	var (
		configFile string
		err        error
	)
	// Build information - populated at build time
	var (
		Version   = "dev"
		BuildTime = "unknown"
		Commit    = "none"
	)

	serverCtx, logger := server.SetupLogger(context.Background(), Version, BuildTime, Commit)
	srv := *server.DefaultServer
	srv.Logger = logger

	flag.StringVar(&configFile, "config", "", "local config file for development (overrides cli options)")
	flag.StringVar(&srv.DBConfigPath, "db_config", "", "path to the json file with database configuration")
	flag.IntVar(&srv.ListenPort, "p", 2416, "port to listen on")
	flag.Parse()

	if configFile != "" {
		srv, err = server.LoadConfigFile(configFile)
		if err != nil {
			logger.Error("loadconfigfile", slog.Any("error", err))
			panic(err)
		}
	}

	if port := os.Getenv("PORT"); port != "" {
		if portNumber, err := strconv.Atoi(port); err == nil {
			srv.ListenPort = portNumber
		}
	}

	err = srv.InitDBConfig()
	if err != nil {
		logger.Error("initdbconfig", slog.Any("error", err))
		panic(err)
	}

	logger.Debug("Initializing persistence and cron jobs")

	// Initialize databases and cron tasks before the Kafka processors and server start
	srv.InitDB()
	srv.InitDynamo()
	// Run the cron job unless it's explicitly disabled.
	if os.Getenv("CRON_ENABLED") != "false" {
		srv.SetupCronTasks()
	}

	logger.Debug("Persistence and cron jobs initialized")

	// add profiling flag to enable profiling routes
	if os.Getenv("PPROF_ENABLE") != "" {
		logger.Debug("Enabling PPROF")
		var addr = ":6061"
		if os.Getenv("PPROF_PORT") != "" {
			addr = os.Getenv("PPROF_PORT")
		}

		// pprof attaches routes to default serve mux
		// host:6061/debug/pprof/
		go func() {
			logger.Error("listenandserve", slog.Any("error", http.ListenAndServe(addr, http.DefaultServeMux)))
		}()
	}

	if os.Getenv("KAFKA_ENABLED") != "false" {
		logger.Debug("Spawning Kafka goroutine")
		server.ServeMetrics()
		go startKafka(srv, logger)
	}

	logger.Debug("Initializing API server")
	err = srv.ListenAndServe(serverCtx, logger)
	if err != nil {
		logger.Error("listenandserve", slog.Any("error", err))
		raven.CaptureErrorAndWait(err, nil)
		logger.Error("listenandserve", slog.Any("error", err))
		panic(err)
	}
}

func startKafka(srv server.Server, logger *slog.Logger) {
	ctx := context.Background()
	logger.Debug("Initializing Kafka consumers")
	err := kafka.StartConsumers(ctx, &srv, logger)

	if err != nil {
		logger.Error("startkafka", slog.Any("error", err))
		// If err is something then start consumer again
		time.Sleep(10 * time.Second)
		startKafka(srv, logger)
	}
}
