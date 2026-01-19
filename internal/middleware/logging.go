// Package middleware provides HTTP middleware for TinyVault.
package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/abdul-hamid-achik/tinyvault/internal/logging"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// Logging returns a middleware that logs HTTP requests.
func Logging(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			requestID := uuid.New().String()
			w.Header().Set("X-Request-ID", requestID)

			wrapped := &responseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			ctx := context.WithValue(r.Context(), logging.RequestIDKey{}, requestID)
			next.ServeHTTP(wrapped, r.WithContext(ctx))

			duration := time.Since(start)
			logger.Info("request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.status,
				"size", wrapped.size,
				"duration", duration,
				"request_id", requestID,
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
			)
		})
	}
}

// Recovery returns a middleware that recovers from panics.
func Recovery(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						"error", err,
						"path", r.URL.Path,
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// GetRequestID returns the request ID from the context, or empty string if not found.
func GetRequestID(ctx context.Context) string {
	return logging.GetRequestID(ctx)
}

// Logger returns a logger with the request_id from the context.
func Logger(ctx context.Context) *slog.Logger {
	return logging.Logger(ctx)
}
