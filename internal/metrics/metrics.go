// Package metrics provides Prometheus metrics for TinyVault.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequestsTotal counts total HTTP requests by method, path, and status.
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tinyvault",
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// HTTPRequestDuration tracks HTTP request duration by method and path.
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "tinyvault",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// HTTPRequestsInFlight tracks the number of in-flight HTTP requests.
	HTTPRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "tinyvault",
			Name:      "http_requests_in_flight",
			Help:      "Number of HTTP requests currently being processed",
		},
	)

	// SecretsTotal tracks the total number of secrets.
	SecretsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "tinyvault",
			Name:      "secrets_total",
			Help:      "Total number of secrets stored",
		},
	)

	// ProjectsTotal tracks the total number of projects.
	ProjectsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "tinyvault",
			Name:      "projects_total",
			Help:      "Total number of projects",
		},
	)

	// ActiveSessionsTotal tracks the number of active sessions.
	ActiveSessionsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "tinyvault",
			Name:      "active_sessions_total",
			Help:      "Number of active user sessions",
		},
	)

	// APITokensTotal tracks the number of API tokens.
	APITokensTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "tinyvault",
			Name:      "api_tokens_total",
			Help:      "Total number of API tokens",
		},
	)

	// EncryptionOperations counts encryption operations.
	EncryptionOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tinyvault",
			Name:      "encryption_operations_total",
			Help:      "Total number of encryption/decryption operations",
		},
		[]string{"operation"}, // "encrypt" or "decrypt"
	)

	// DatabaseConnections tracks database connection pool stats.
	DatabaseConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "tinyvault",
			Name:      "database_connections",
			Help:      "Database connection pool statistics",
		},
		[]string{"state"}, // "open", "idle", "in_use"
	)
)
