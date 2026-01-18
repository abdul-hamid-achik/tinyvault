// Package config provides application configuration management.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all application configuration.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Security SecurityConfig
	GitHub   GitHubConfig
	RateLimit RateLimitConfig
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host           string
	Port           int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	RequestTimeout time.Duration
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	URL             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	URL          string
	MaxRetries   int
	PoolSize     int
	MinIdleConns int
}

// SecurityConfig holds security-related settings.
type SecurityConfig struct {
	MasterKey          []byte
	Environment        string
	LogLevel           string
	CleanupInterval    time.Duration
	AuditRetention     time.Duration
	MaxRequestBodySize int64
	MaxLoginAttempts   int
	LockoutDuration    time.Duration
}

// GitHubConfig holds GitHub OAuth settings.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

// RateLimitConfig holds rate limiting settings.
type RateLimitConfig struct {
	Requests int
	Window   time.Duration
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Read from environment
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	cfg := &Config{}

	// Server
	cfg.Server = ServerConfig{
		Host:           v.GetString("server.host"),
		Port:           v.GetInt("server.port"),
		ReadTimeout:    v.GetDuration("server.read_timeout"),
		WriteTimeout:   v.GetDuration("server.write_timeout"),
		IdleTimeout:    v.GetDuration("server.idle_timeout"),
		RequestTimeout: v.GetDuration("server.request_timeout"),
	}

	// Database
	cfg.Database = DatabaseConfig{
		URL:             v.GetString("database.url"),
		MaxOpenConns:    v.GetInt("database.max_open_conns"),
		MaxIdleConns:    v.GetInt("database.max_idle_conns"),
		ConnMaxLifetime: v.GetDuration("database.conn_max_lifetime"),
		ConnMaxIdleTime: v.GetDuration("database.conn_max_idle_time"),
	}

	// Redis
	cfg.Redis = RedisConfig{
		URL:          v.GetString("redis.url"),
		MaxRetries:   v.GetInt("redis.max_retries"),
		PoolSize:     v.GetInt("redis.pool_size"),
		MinIdleConns: v.GetInt("redis.min_idle_conns"),
	}

	// Security
	environment := v.GetString("env")
	masterKeyStr := v.GetString("encryption.key")
	var masterKey []byte

	if masterKeyStr != "" {
		var err error
		masterKey, err = base64.StdEncoding.DecodeString(masterKeyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid ENCRYPTION_KEY: must be valid base64: %w", err)
		}
		if len(masterKey) != 32 {
			return nil, fmt.Errorf("invalid ENCRYPTION_KEY: must be 32 bytes (got %d bytes). Generate with: openssl rand -base64 32", len(masterKey))
		}
	} else if environment == "development" {
		// Auto-generate a random key for development
		masterKey = make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			return nil, fmt.Errorf("failed to generate development encryption key: %w", err)
		}
		slog.Warn("ENCRYPTION_KEY not set - using auto-generated key for development. Data will not persist across restarts!")
	}

	cfg.Security = SecurityConfig{
		MasterKey:          masterKey,
		Environment:        environment,
		LogLevel:           v.GetString("log.level"),
		CleanupInterval:    v.GetDuration("security.cleanup_interval"),
		AuditRetention:     v.GetDuration("security.audit_retention"),
		MaxRequestBodySize: v.GetInt64("security.max_request_body_size"),
		MaxLoginAttempts:   v.GetInt("security.max_login_attempts"),
		LockoutDuration:    v.GetDuration("security.lockout_duration"),
	}

	// GitHub
	cfg.GitHub = GitHubConfig{
		ClientID:     v.GetString("github.client_id"),
		ClientSecret: v.GetString("github.client_secret"),
		CallbackURL:  v.GetString("github.callback_url"),
	}

	// Rate limiting
	cfg.RateLimit = RateLimitConfig{
		Requests: v.GetInt("rate_limit.requests"),
		Window:   v.GetDuration("rate_limit.window"),
	}

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// setDefaults configures default values.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 15*time.Second)
	v.SetDefault("server.write_timeout", 15*time.Second)
	v.SetDefault("server.idle_timeout", 60*time.Second)
	v.SetDefault("server.request_timeout", 30*time.Second)

	// Database defaults
	v.SetDefault("database.url", "postgres://tinyvault:tinyvault@localhost:5432/tinyvault?sslmode=disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", 5*time.Minute)
	v.SetDefault("database.conn_max_idle_time", 5*time.Minute)

	// Redis defaults
	v.SetDefault("redis.url", "redis://localhost:6379/0")
	v.SetDefault("redis.max_retries", 3)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 2)

	// Security defaults
	v.SetDefault("env", "development")
	v.SetDefault("log.level", "info")
	v.SetDefault("security.cleanup_interval", 1*time.Hour)
	v.SetDefault("security.audit_retention", 90*24*time.Hour) // 90 days
	v.SetDefault("security.max_request_body_size", 1*1024*1024) // 1MB
	v.SetDefault("security.max_login_attempts", 5)
	v.SetDefault("security.lockout_duration", 15*time.Minute)

	// Rate limiting defaults
	v.SetDefault("rate_limit.requests", 100)
	v.SetDefault("rate_limit.window", 60*time.Second)
}

// Validate checks that all required configuration is present.
func (c *Config) Validate() error {
	if c.Database.URL == "" {
		return fmt.Errorf("database URL is required")
	}

	if c.IsProduction() {
		if len(c.Security.MasterKey) == 0 {
			return fmt.Errorf("ENCRYPTION_KEY is required in production. Generate with: openssl rand -base64 32")
		}
		if c.GitHub.ClientID == "" || c.GitHub.ClientSecret == "" {
			return fmt.Errorf("GitHub OAuth credentials are required in production")
		}
	}

	return nil
}

// IsProduction returns true if running in production mode.
func (c *Config) IsProduction() bool {
	return c.Security.Environment == "production"
}

// IsDevelopment returns true if running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.Security.Environment == "development"
}

// ServerAddr returns the full server address.
func (c *Config) ServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}
