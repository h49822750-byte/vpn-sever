//go:build linux

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"vpn-server/internal/client"
	"vpn-server/internal/config"
)

func main() {
	configPath := flag.String("config", "/etc/vpn/client.yaml", "Path to client YAML configuration file")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("failed to load client configuration", "err", err)
		os.Exit(1)
	}

	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(cfg.LogLevel)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	cli, err := client.NewLinuxClient(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize vpn-client", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cli.ConnectAndRun(ctx, nil); err != nil && ctx.Err() == nil {
		logger.Error("vpn-client exited with error", "err", err)
		os.Exit(1)
	}
	logger.Info("vpn-client shut down cleanly")
}
