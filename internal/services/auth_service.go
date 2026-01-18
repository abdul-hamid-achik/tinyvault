package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/database/db"
)

const (
	// SessionDuration is the default session lifetime.
	SessionDuration = 7 * 24 * time.Hour // 7 days

	// SessionTokenLength is the length of session tokens in bytes.
	SessionTokenLength = 32
)

// AuthService handles authentication and session management.
type AuthService struct {
	queries         *db.Queries
	pool            *pgxpool.Pool
	userService     *UserService
	maxAttempts     int
	lockoutDuration time.Duration
}

// NewAuthService creates a new AuthService.
func NewAuthService(pool *pgxpool.Pool, userService *UserService, maxAttempts int, lockoutDuration time.Duration) *AuthService {
	return &AuthService{
		queries:         db.New(pool),
		pool:            pool,
		userService:     userService,
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
	}
}

// Session represents a user session.
type Session struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Token        string // Only set when creating
	IPAddress    string
	UserAgent    string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	LastActiveAt time.Time
}

// SessionWithUser represents a session with user data.
type SessionWithUser struct {
	Session
	User *User
}

// CreateSession creates a new session for a user.
func (s *AuthService) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*Session, error) {
	// Generate a secure session token
	token, err := crypto.GenerateTokenString(SessionTokenLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Hash the token for storage
	tokenHash := crypto.HashTokenString(token)

	var ip *netip.Addr
	if ipAddress != "" {
		parsed, err := netip.ParseAddr(ipAddress)
		if err == nil {
			ip = &parsed
		}
	}

	var ua *string
	if userAgent != "" {
		ua = &userAgent
	}

	expiresAt := time.Now().Add(SessionDuration)

	dbSession, err := s.queries.CreateSession(ctx, db.CreateSessionParams{
		UserID:    userID,
		TokenHash: tokenHash,
		IpAddress: ip,
		UserAgent: ua,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	ipStr := ""
	if dbSession.IpAddress != nil {
		ipStr = dbSession.IpAddress.String()
	}

	uaStr := ""
	if dbSession.UserAgent != nil {
		uaStr = *dbSession.UserAgent
	}

	return &Session{
		ID:           dbSession.ID,
		UserID:       dbSession.UserID,
		Token:        token, // Return the plaintext token to the user
		IPAddress:    ipStr,
		UserAgent:    uaStr,
		ExpiresAt:    dbSession.ExpiresAt,
		CreatedAt:    dbSession.CreatedAt,
		LastActiveAt: dbSession.LastActiveAt,
	}, nil
}

// ValidateSession validates a session token and returns the session with user.
func (s *AuthService) ValidateSession(ctx context.Context, token string) (*SessionWithUser, error) {
	// Hash the provided token
	tokenHash := crypto.HashTokenString(token)

	// Look up the session
	row, err := s.queries.GetSessionWithUser(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}

	// Update last active time asynchronously with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.queries.UpdateSessionActivity(ctx, row.ID); err != nil {
			slog.Error("failed to update session activity", "session_id", row.ID, "error", err)
		}
	}()

	ipStr := ""
	if row.IpAddress != nil {
		ipStr = row.IpAddress.String()
	}

	uaStr := ""
	if row.UserAgent != nil {
		uaStr = *row.UserAgent
	}

	return &SessionWithUser{
		Session: Session{
			ID:           row.ID,
			UserID:       row.UserID,
			IPAddress:    ipStr,
			UserAgent:    uaStr,
			ExpiresAt:    row.ExpiresAt,
			CreatedAt:    row.CreatedAt,
			LastActiveAt: row.LastActiveAt,
		},
		User: &User{
			ID:        row.UserID_2,
			GitHubID:  row.GithubID,
			Email:     row.Email,
			Username:  row.Username,
			Name:      row.Name,
			AvatarURL: row.AvatarUrl,
		},
	}, nil
}

// DeleteSession deletes a session by token.
func (s *AuthService) DeleteSession(ctx context.Context, token string) error {
	tokenHash := crypto.HashTokenString(token)
	if err := s.queries.DeleteSessionByHash(ctx, tokenHash); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// DeleteAllSessions deletes all sessions for a user.
func (s *AuthService) DeleteAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := s.queries.DeleteAllSessionsByUser(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete sessions: %w", err)
	}
	return nil
}

// CleanupExpiredSessions removes expired sessions from the database.
func (s *AuthService) CleanupExpiredSessions(ctx context.Context) error {
	if err := s.queries.DeleteExpiredSessions(ctx); err != nil {
		return fmt.Errorf("failed to cleanup sessions: %w", err)
	}
	return nil
}

// ListActiveSessions lists all active sessions for a user.
func (s *AuthService) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error) {
	dbSessions, err := s.queries.ListActiveSessionsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	sessions := make([]*Session, len(dbSessions))
	for i, sess := range dbSessions {
		ipStr := ""
		if sess.IpAddress != nil {
			ipStr = sess.IpAddress.String()
		}

		uaStr := ""
		if sess.UserAgent != nil {
			uaStr = *sess.UserAgent
		}

		sessions[i] = &Session{
			ID:           sess.ID,
			UserID:       sess.UserID,
			IPAddress:    ipStr,
			UserAgent:    uaStr,
			ExpiresAt:    sess.ExpiresAt,
			CreatedAt:    sess.CreatedAt,
			LastActiveAt: sess.LastActiveAt,
		}
	}

	return sessions, nil
}

// ErrAccountLocked is returned when an account is temporarily locked due to too many failed login attempts.
var ErrAccountLocked = fmt.Errorf("account temporarily locked due to too many failed login attempts")

// IsAccountLocked checks if an account is locked due to too many failed login attempts.
func (s *AuthService) IsAccountLocked(ctx context.Context, email string) (bool, error) {
	if s.maxAttempts <= 0 {
		return false, nil // Lockout disabled
	}

	since := time.Now().Add(-s.lockoutDuration)
	count, err := s.queries.CountRecentFailedAttempts(ctx, db.CountRecentFailedAttemptsParams{
		Email:     email,
		CreatedAt: since,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check login attempts: %w", err)
	}

	return count >= int64(s.maxAttempts), nil
}

// RecordLoginAttempt records a login attempt.
func (s *AuthService) RecordLoginAttempt(ctx context.Context, email, ipAddress string, success bool) {
	var ip *netip.Addr
	if ipAddress != "" {
		if parsed, err := netip.ParseAddr(ipAddress); err == nil {
			ip = &parsed
		}
	}

	if err := s.queries.RecordLoginAttempt(ctx, db.RecordLoginAttemptParams{
		Email:     email,
		IpAddress: ip,
		Success:   success,
	}); err != nil {
		slog.Error("failed to record login attempt", "email", email, "error", err)
	}
}

// CleanupLoginAttempts removes old login attempts from the database.
func (s *AuthService) CleanupLoginAttempts(ctx context.Context, retention time.Duration) error {
	cutoff := time.Now().Add(-retention)
	if err := s.queries.CleanupOldLoginAttempts(ctx, cutoff); err != nil {
		return fmt.Errorf("failed to cleanup login attempts: %w", err)
	}
	return nil
}
