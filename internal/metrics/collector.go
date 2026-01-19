// Package metrics provides Prometheus metrics for TinyVault.
package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdul-hamid-achik/tinyvault/internal/database/db"
)

// StartCollector starts a background goroutine that periodically collects metrics.
// It updates gauge metrics for database connections and business metrics.
func StartCollector(ctx context.Context, pool *pgxpool.Pool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Collect immediately on startup
	collectMetrics(ctx, pool)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collectMetrics(ctx, pool)
		}
	}
}

// collectMetrics collects all gauge metrics from the database.
func collectMetrics(ctx context.Context, pool *pgxpool.Pool) {
	// Collect database connection pool stats
	collectDatabaseStats(pool)

	// Collect business metrics
	collectBusinessMetrics(ctx, pool)
}

// collectDatabaseStats updates database connection pool metrics.
func collectDatabaseStats(pool *pgxpool.Pool) {
	stats := pool.Stat()

	DatabaseConnections.WithLabelValues("in_use").Set(float64(stats.AcquiredConns()))
	DatabaseConnections.WithLabelValues("idle").Set(float64(stats.IdleConns()))
	DatabaseConnections.WithLabelValues("max_open").Set(float64(stats.MaxConns()))
}

// collectBusinessMetrics queries the database for business metrics.
func collectBusinessMetrics(ctx context.Context, pool *pgxpool.Pool) {
	queries := db.New(pool)

	// Use a timeout for the metric collection queries
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Count secrets
	if count, err := queries.CountAllSecrets(ctx); err == nil {
		SecretsTotal.Set(float64(count))
	} else {
		slog.Debug("failed to count secrets for metrics", "error", err)
	}

	// Count projects
	if count, err := queries.CountAllProjects(ctx); err == nil {
		ProjectsTotal.Set(float64(count))
	} else {
		slog.Debug("failed to count projects for metrics", "error", err)
	}

	// Count active sessions
	if count, err := queries.CountActiveSessions(ctx); err == nil {
		ActiveSessionsTotal.Set(float64(count))
	} else {
		slog.Debug("failed to count active sessions for metrics", "error", err)
	}

	// Count active API tokens
	if count, err := queries.CountActiveAPITokens(ctx); err == nil {
		APITokensTotal.Set(float64(count))
	} else {
		slog.Debug("failed to count active API tokens for metrics", "error", err)
	}
}
