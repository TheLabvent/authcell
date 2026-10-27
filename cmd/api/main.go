package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"authcell/internal/config"
	"authcell/internal/database"
	"authcell/internal/server"

	_ "github.com/joho/godotenv/autoload"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe /v1/health on PORT and exit (for container health checks)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()})))

	if err := run(); err != nil {
		slog.Error("authcell stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	db, err := database.Connect(connectCtx, cfg.DatabaseURL, database.Options{
		MaxConns: cfg.DBMaxConns, MinConns: cfg.DBMinConns, ConnMaxLifetime: cfg.DBConnMaxLifetime,
	})
	cancel()
	if err != nil {
		return err
	}
	defer db.Close()

	if cfg.UsageRetention > 0 {
		go pruneUsage(ctx, db, cfg.UsageRetention)
	}

	app := server.New(cfg, db, version)

	listenErr := make(chan error, 1)
	go func() {
		addr := ":" + strconv.Itoa(cfg.Port)
		slog.Info("authcell listening", "addr", addr, "version", version, "env", cfg.Env,
			"verify_protected", cfg.VerifyToken != "")
		listenErr <- app.Listen(addr)
	}()

	select {
	case err := <-listenErr:
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	stop() // a second Ctrl+C now kills the process
	if err := app.ShutdownWithTimeout(10 * time.Second); err != nil {
		slog.Warn("forced shutdown", "error", err)
	}
	slog.Info("shutdown complete")
	return nil
}

// pruneUsage deletes old usage rows once an hour so the table doesn't grow forever.
func pruneUsage(ctx context.Context, db database.Service, retention time.Duration) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		pctx, cancel := context.WithTimeout(ctx, time.Minute)
		n, err := db.PruneUsage(pctx, time.Now().Add(-retention))
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("usage prune failed", "error", err)
		} else if n > 0 {
			slog.Info("pruned usage rows", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func logLevel() slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(os.Getenv("LOG_LEVEL"))); err != nil {
		return slog.LevelInfo
	}
	return l
}
