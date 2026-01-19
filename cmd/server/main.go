// Package main is the entry point for the TinyVault server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdul-hamid-achik/tinyvault/internal/config"
	"github.com/abdul-hamid-achik/tinyvault/internal/handlers"
	"github.com/abdul-hamid-achik/tinyvault/internal/metrics"
	"github.com/abdul-hamid-achik/tinyvault/internal/services"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup logger
	logLevel := slog.LevelInfo
	switch cfg.Security.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	logger.Info("starting TinyVault",
		"version", version,
		"env", cfg.Security.Environment,
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to PostgreSQL
	logger.Info("connecting to PostgreSQL")
	dbPool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer dbPool.Close()

	if pingErr := dbPool.Ping(ctx); pingErr != nil {
		return fmt.Errorf("failed to ping database: %w", pingErr)
	}
	logger.Info("connected to PostgreSQL")

	// Connect to Redis
	logger.Info("connecting to Redis")
	opt, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %w", err)
	}
	redisClient := redis.NewClient(opt)
	defer func() {
		if err := redisClient.Close(); err != nil {
			logger.Error("failed to close redis client", "error", err)
		}
	}()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to ping Redis: %w", err)
	}
	logger.Info("connected to Redis")

	// Initialize services
	userService := services.NewUserService(dbPool)
	projectService := services.NewProjectService(dbPool, cfg.Security.MasterKey)
	secretService := services.NewSecretService(dbPool, projectService)
	authService := services.NewAuthService(dbPool, userService, cfg.Security.MaxLoginAttempts, cfg.Security.LockoutDuration)
	tokenService := services.NewTokenService(dbPool)
	auditService := services.NewAuditService(dbPool)

	// Create router
	deps := &handlers.Dependencies{
		Config:         cfg,
		DB:             dbPool,
		Redis:          redisClient,
		Logger:         logger,
		UserService:    userService,
		ProjectService: projectService,
		SecretService:  secretService,
		AuthService:    authService,
		TokenService:   tokenService,
		AuditService:   auditService,
	}

	router := handlers.NewRouter(deps)

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.ServerAddr(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start background tasks
	go func() {
		ticker := time.NewTicker(cfg.Security.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Cleanup expired sessions
				if err := authService.CleanupExpiredSessions(ctx); err != nil {
					logger.Error("failed to cleanup sessions", "error", err)
				}

				// Cleanup old audit logs
				if err := auditService.Cleanup(ctx, cfg.Security.AuditRetention); err != nil {
					logger.Error("failed to cleanup audit logs", "error", err)
				}

				// Cleanup old login attempts (keep for 24 hours)
				if err := authService.CleanupLoginAttempts(ctx, 24*time.Hour); err != nil {
					logger.Error("failed to cleanup login attempts", "error", err)
				}
			}
		}
	}()

	// Start metrics collector (every 30 seconds)
	go metrics.StartCollector(ctx, dbPool, 30*time.Second)

	// Start server in goroutine
	go func() {
		logger.Info("server listening",
			"addr", cfg.ServerAddr(),
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err)
			cancel()
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		logger.Info("shutting down server")
	case <-ctx.Done():
		logger.Info("context canceled")
	}

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	logger.Info("server stopped")
	return nil
}
