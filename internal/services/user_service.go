// Package services contains business logic for TinyVault.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/database/db"
	"github.com/abdul-hamid-achik/tinyvault/internal/logging"
)

// UserService handles user-related business logic.
type UserService struct {
	queries *db.Queries
	pool    *pgxpool.Pool
}

// NewUserService creates a new UserService.
func NewUserService(pool *pgxpool.Pool) *UserService {
	return &UserService{
		queries: db.New(pool),
		pool:    pool,
	}
}

// GitHubUser represents a GitHub user from OAuth.
type GitHubUser struct {
	ID        int64
	Email     string
	Username  string
	Name      string
	AvatarURL string
}

// User represents a TinyVault user.
type User struct {
	ID            uuid.UUID
	GitHubID      *int64
	Email         string
	Username      string
	Name          *string
	AvatarURL     *string
	PasswordHash  *string
	AuthProvider  string
	EmailVerified bool
}

// Auth provider constants
const (
	AuthProviderGitHub = "github"
	AuthProviderEmail  = "email"
)

// Errors
var (
	ErrEmailExists        = errors.New("email already registered")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
)

// dbUserToUser converts a db.User to a services.User
func dbUserToUser(dbUser db.User) *User {
	return &User{
		ID:            dbUser.ID,
		GitHubID:      dbUser.GithubID,
		Email:         dbUser.Email,
		Username:      dbUser.Username,
		Name:          dbUser.Name,
		AvatarURL:     dbUser.AvatarUrl,
		PasswordHash:  dbUser.PasswordHash,
		AuthProvider:  dbUser.AuthProvider,
		EmailVerified: dbUser.EmailVerified,
	}
}

// CreateOrUpdate creates a new user or updates an existing one from GitHub OAuth.
func (s *UserService) CreateOrUpdate(ctx context.Context, gu *GitHubUser) (*User, error) {
	log := logging.Logger(ctx)

	var name, avatar *string
	if gu.Name != "" {
		name = &gu.Name
	}
	if gu.AvatarURL != "" {
		avatar = &gu.AvatarURL
	}

	githubID := gu.ID
	dbUser, err := s.queries.UpsertUser(ctx, db.UpsertUserParams{
		GithubID:  &githubID,
		Email:     gu.Email,
		Username:  gu.Username,
		Name:      name,
		AvatarUrl: avatar,
	})
	if err != nil {
		log.Error("user_upsert_failed", "github_id", githubID, "error", err)
		return nil, fmt.Errorf("failed to upsert user: %w", err)
	}

	log.Debug("user_upserted", "user_id", dbUser.ID, "github_id", githubID)
	return dbUserToUser(dbUser), nil
}

// CreateFromEmail creates a new user with email/password authentication.
func (s *UserService) CreateFromEmail(ctx context.Context, email, password, username string) (*User, error) {
	log := logging.Logger(ctx)

	// Check if email already exists for email auth
	exists, err := s.queries.CheckEmailExists(ctx, db.CheckEmailExistsParams{
		Email:        email,
		AuthProvider: AuthProviderEmail,
	})
	if err != nil {
		log.Error("email_check_failed", "email", email, "error", err)
		return nil, fmt.Errorf("failed to check email: %w", err)
	}
	if exists {
		return nil, ErrEmailExists
	}

	// Hash password
	passwordHash, err := crypto.HashPassword(password)
	if err != nil {
		log.Error("password_hash_failed", "error", err)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	dbUser, err := s.queries.CreateUserFromEmail(ctx, db.CreateUserFromEmailParams{
		Email:        email,
		Username:     username,
		PasswordHash: &passwordHash,
	})
	if err != nil {
		log.Error("user_creation_failed", "email", email, "error", err)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	log.Debug("user_created", "user_id", dbUser.ID, "email", email)
	return dbUserToUser(dbUser), nil
}

// AuthenticateByEmail validates email/password and returns the user if valid.
func (s *UserService) AuthenticateByEmail(ctx context.Context, email, password string) (*User, error) {
	log := logging.Logger(ctx)

	dbUser, err := s.queries.GetUserByEmailForAuth(ctx, email)
	if err != nil {
		log.Debug("auth_user_not_found", "email", email)
		return nil, ErrInvalidCredentials
	}

	if dbUser.PasswordHash == nil {
		log.Debug("auth_no_password_hash", "email", email)
		return nil, ErrInvalidCredentials
	}

	if !crypto.VerifyPassword(password, *dbUser.PasswordHash) {
		log.Debug("auth_password_mismatch", "email", email)
		return nil, ErrInvalidCredentials
	}

	log.Debug("auth_success", "user_id", dbUser.ID, "email", email)
	return dbUserToUser(dbUser), nil
}

// GetByID retrieves a user by their ID.
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	dbUser, err := s.queries.GetUserByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return dbUserToUser(dbUser), nil
}

// GetByGitHubID retrieves a user by their GitHub ID.
func (s *UserService) GetByGitHubID(ctx context.Context, githubID int64) (*User, error) {
	dbUser, err := s.queries.GetUserByGitHubID(ctx, &githubID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by GitHub ID: %w", err)
	}

	return dbUserToUser(dbUser), nil
}

// GetByEmail retrieves a user by their email.
func (s *UserService) GetByEmail(ctx context.Context, email string) (*User, error) {
	dbUser, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return dbUserToUser(dbUser), nil
}
