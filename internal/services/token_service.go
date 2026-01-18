package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/database/db"
)

const (
	// APITokenLength is the length of API tokens in bytes.
	APITokenLength = 32
)

// TokenService handles API token management.
type TokenService struct {
	queries *db.Queries
	pool    *pgxpool.Pool
}

// NewTokenService creates a new TokenService.
func NewTokenService(pool *pgxpool.Pool) *TokenService {
	return &TokenService{
		queries: db.New(pool),
		pool:    pool,
	}
}

// APIToken represents an API token.
type APIToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Name       string
	Token      string // Only set when creating
	Scopes     []string
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	CreatedAt  time.Time
}

// APITokenWithUser represents an API token with user data.
type APITokenWithUser struct {
	APIToken
	User *User
}

// Create creates a new API token for a user.
func (s *TokenService) Create(ctx context.Context, userID uuid.UUID, name string, scopes []string, expiresAt *time.Time) (*APIToken, error) {
	// Generate a secure token
	token, err := crypto.GenerateTokenString(APITokenLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate API token: %w", err)
	}

	// Hash the token for storage
	tokenHash := crypto.HashTokenString(token)

	var pgExpiresAt pgtype.Timestamptz
	if expiresAt != nil {
		pgExpiresAt = pgtype.Timestamptz{Time: *expiresAt, Valid: true}
	}

	dbToken, err := s.queries.CreateAPIToken(ctx, db.CreateAPITokenParams{
		UserID:    userID,
		Name:      name,
		TokenHash: tokenHash,
		Scopes:    scopes,
		ExpiresAt: pgExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create API token: %w", err)
	}

	var lastUsed *time.Time
	if dbToken.LastUsedAt.Valid {
		lastUsed = &dbToken.LastUsedAt.Time
	}

	var expires *time.Time
	if dbToken.ExpiresAt.Valid {
		expires = &dbToken.ExpiresAt.Time
	}

	return &APIToken{
		ID:         dbToken.ID,
		UserID:     dbToken.UserID,
		Name:       dbToken.Name,
		Token:      token, // Return plaintext token to user (only time it's available)
		Scopes:     dbToken.Scopes,
		LastUsedAt: lastUsed,
		ExpiresAt:  expires,
		CreatedAt:  dbToken.CreatedAt,
	}, nil
}

// Validate validates an API token and returns the token with user data.
func (s *TokenService) Validate(ctx context.Context, token string) (*APITokenWithUser, error) {
	// Hash the provided token
	tokenHash := crypto.HashTokenString(token)

	// Look up the token with user
	row, err := s.queries.GetAPITokenWithUser(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid API token: %w", err)
	}

	// Update last used time asynchronously with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.queries.UpdateAPITokenLastUsed(ctx, row.ID); err != nil {
			slog.Error("failed to update API token last used", "token_id", row.ID, "error", err)
		}
	}()

	var lastUsed *time.Time
	if row.LastUsedAt.Valid {
		lastUsed = &row.LastUsedAt.Time
	}

	var expires *time.Time
	if row.ExpiresAt.Valid {
		expires = &row.ExpiresAt.Time
	}

	return &APITokenWithUser{
		APIToken: APIToken{
			ID:         row.ID,
			UserID:     row.UserID,
			Name:       row.Name,
			Scopes:     row.Scopes,
			LastUsedAt: lastUsed,
			ExpiresAt:  expires,
			CreatedAt:  row.CreatedAt,
		},
		User: &User{
			ID:        row.UserID_2,
			GitHubID:  row.GithubID,
			Email:     row.Email,
			Username:  row.Username,
			Name:      row.Name_2,
			AvatarURL: row.AvatarUrl,
		},
	}, nil
}

// List lists all API tokens for a user.
func (s *TokenService) List(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]*APIToken, error) {
	dbTokens, err := s.queries.ListAPITokensByUser(ctx, db.ListAPITokensByUserParams{
		UserID: userID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list API tokens: %w", err)
	}

	tokens := make([]*APIToken, len(dbTokens))
	for i, t := range dbTokens {
		var lastUsed *time.Time
		if t.LastUsedAt.Valid {
			lastUsed = &t.LastUsedAt.Time
		}

		var expires *time.Time
		if t.ExpiresAt.Valid {
			expires = &t.ExpiresAt.Time
		}

		tokens[i] = &APIToken{
			ID:         t.ID,
			UserID:     t.UserID,
			Name:       t.Name,
			Scopes:     t.Scopes,
			LastUsedAt: lastUsed,
			ExpiresAt:  expires,
			CreatedAt:  t.CreatedAt,
		}
	}

	return tokens, nil
}

// ListActive lists all active (non-expired, non-revoked) tokens for a user.
func (s *TokenService) ListActive(ctx context.Context, userID uuid.UUID) ([]*APIToken, error) {
	dbTokens, err := s.queries.ListActiveAPITokensByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active API tokens: %w", err)
	}

	tokens := make([]*APIToken, len(dbTokens))
	for i, t := range dbTokens {
		var lastUsed *time.Time
		if t.LastUsedAt.Valid {
			lastUsed = &t.LastUsedAt.Time
		}

		var expires *time.Time
		if t.ExpiresAt.Valid {
			expires = &t.ExpiresAt.Time
		}

		tokens[i] = &APIToken{
			ID:         t.ID,
			UserID:     t.UserID,
			Name:       t.Name,
			Scopes:     t.Scopes,
			LastUsedAt: lastUsed,
			ExpiresAt:  expires,
			CreatedAt:  t.CreatedAt,
		}
	}

	return tokens, nil
}

// Revoke revokes an API token.
func (s *TokenService) Revoke(ctx context.Context, tokenID, userID uuid.UUID) error {
	if err := s.queries.RevokeAPIToken(ctx, db.RevokeAPITokenParams{
		ID:     tokenID,
		UserID: userID,
	}); err != nil {
		return fmt.Errorf("failed to revoke API token: %w", err)
	}
	return nil
}

// RevokeAll revokes all API tokens for a user.
func (s *TokenService) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	if err := s.queries.RevokeAllAPITokensByUser(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke all API tokens: %w", err)
	}
	return nil
}

// HasScope checks if a token has a specific scope.
func HasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required || scope == "*" {
			return true
		}
	}
	return false
}
