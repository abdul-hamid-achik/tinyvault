// Package logging provides context-aware logging utilities.
package logging

import (
	"context"
	"log/slog"
)

// RequestIDKey is the context key for the request ID.
type RequestIDKey struct{}

// GetRequestID returns the request ID from the context, or empty string if not found.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// Logger returns a logger with the request_id from the context.
func Logger(ctx context.Context) *slog.Logger {
	requestID := GetRequestID(ctx)
	if requestID != "" {
		return slog.Default().With("request_id", requestID)
	}
	return slog.Default()
}
