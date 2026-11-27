//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"vpn-server/internal/config"
	"vpn-server/internal/control"
	"vpn-server/internal/metrics"
	"vpn-server/internal/netstack"
	"vpn-server/internal/server"
)

func main() {
	configPath := flag.String("config", "/etc/vpn/server.yaml", "Path to server YAML configuration file")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("failed to load server configuration", "err", err)
		os.Exit(1)
	}

	logger := newJSONLogger(cfg.Observability.LogLevel)
	collector := metrics.NewCollector(true)

	srv, err := server.NewLinuxServer(cfg, collector, logger)
	if err != nil {
		logger.Error("failed to initialize vpn-server", "err", err)
		os.Exit(1)
	}

	var ctrlSrv *control.Server
	if cfg.Control.SocketPath != "" {
		ctrlSrv, err = control.NewServer(cfg.Control.SocketPath, srv, logger)
		if err != nil {
			logger.Error("failed to bind control socket", "socket", cfg.Control.SocketPath, "err", err)
			os.Exit(1)
		}
	}

	var metricsLn net.Listener
	var metricsHTTP *http.Server
	if cfg.Observability.MetricsAddr != "" {
		metricsLn, err = net.Listen("tcp", cfg.Observability.MetricsAddr)
		if err != nil {
			logger.Error("failed to bind prometheus metrics address", "addr", cfg.Observability.MetricsAddr, "err", err)
			os.Exit(1)
		}
		mux := http.NewServeMux()
		mux.Handle("/metrics", collector.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
		metricsHTTP = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
	}

	// Drop root privileges after completing CAP_NET_ADMIN & socket bind initialization.
	if cfg.DropUser != "" {
		if err := netstack.DropPrivileges(cfg.DropUser); err != nil {
			logger.Error("failed to drop privileges", "drop_user", cfg.DropUser, "err", err)
			os.Exit(1)
		}
		logger.Info("dropped privileges", "user", cfg.DropUser)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if ctrlSrv != nil {
		go func() {
			logger.Info("control plane listening", "socket", cfg.Control.SocketPath)
			if err := ctrlSrv.Serve(); err != nil {
				logger.Error("control plane exited with error", "err", err)
			}
		}()
	}

	if metricsHTTP != nil {
		go func() {
			logger.Info("prometheus metrics listening", "addr", metricsLn.Addr().String())
			if err := metricsHTTP.Serve(metricsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics server exited with error", "err", err)
			}
		}()
	}

	if err := srv.Run(ctx); err != nil {
		logger.Error("vpn-server exited with error", "err", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ctrlSrv != nil {
		_ = ctrlSrv.Shutdown(shutdownCtx)
	}
	if metricsHTTP != nil {
		_ = metricsHTTP.Shutdown(shutdownCtx)
	}
	logger.Info("vpn-server shut down cleanly")
}

func newJSONLogger(levelStr string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
