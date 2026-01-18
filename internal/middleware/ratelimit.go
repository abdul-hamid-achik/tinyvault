package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter provides rate limiting functionality using Redis.
type RateLimiter struct {
	client   *redis.Client
	requests int
	window   time.Duration
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter(client *redis.Client, requests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		client:   client,
		requests: requests,
		window:   window,
	}
}

// Allow checks if a request is allowed for the given key.
func (rl *RateLimiter) Allow(ctx context.Context, key string) (bool, int, error) {
	redisKey := fmt.Sprintf("ratelimit:%s", key)

	// Use a Lua script for atomic increment and check
	script := redis.NewScript(`
		local current = redis.call("INCR", KEYS[1])
		if current == 1 then
			redis.call("EXPIRE", KEYS[1], ARGV[1])
		end
		return current
	`)

	result, err := script.Run(ctx, rl.client, []string{redisKey}, int(rl.window.Seconds())).Int()
	if err != nil {
		return false, 0, err
	}

	remaining := rl.requests - result
	if remaining < 0 {
		remaining = 0
	}

	return result <= rl.requests, remaining, nil
}

// RateLimit returns middleware that rate limits requests.
func RateLimit(limiter *RateLimiter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use IP address as the rate limit key
			key := r.RemoteAddr

			// If authenticated, use user ID instead
			if user := GetUser(r.Context()); user != nil {
				key = "user:" + user.ID.String()
			}

			allowed, remaining, err := limiter.Allow(r.Context(), key)
			if err != nil {
				// If Redis is down, fail closed and return 503
				slog.Error("rate limiter unavailable", "key", key, "error", err)
				http.Error(w, `{"error":{"code":"SERVICE_UNAVAILABLE","message":"Service temporarily unavailable"}}`, http.StatusServiceUnavailable)
				return
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limiter.requests))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(limiter.window).Unix()))

			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(limiter.window.Seconds())))
				http.Error(w, `{"error":{"code":"RATE_LIMITED","message":"Too many requests"}}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitAPI returns a stricter rate limiter for API endpoints.
func RateLimitAPI(limiter *RateLimiter) func(next http.Handler) http.Handler {
	return RateLimit(limiter)
}
