package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/database/db"
)

// SecretService handles secret-related business logic.
type SecretService struct {
	queries        *db.Queries
	pool           *pgxpool.Pool
	projectService *ProjectService
}

// NewSecretService creates a new SecretService.
func NewSecretService(pool *pgxpool.Pool, projectService *ProjectService) *SecretService {
	return &SecretService{
		queries:        db.New(pool),
		pool:           pool,
		projectService: projectService,
	}
}

// Secret represents a TinyVault secret (without the value for listing).
type Secret struct {
	ID        uuid.UUID
	ProjectID uuid.UUID
	Key       string
	Version   int32
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SecretWithValue represents a secret with its decrypted value.
type SecretWithValue struct {
	Secret
	Value []byte
}

// Create creates a new secret with encrypted value.
func (s *SecretService) Create(ctx context.Context, projectID uuid.UUID, key string, value []byte) (*Secret, error) {
	// Get the project's DEK
	dek, err := s.projectService.GetDecryptedDEK(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project DEK: %w", err)
	}
	defer crypto.ZeroBytes(dek)

	// Encrypt the secret value
	encryptedValue, err := crypto.Encrypt(dek, value)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Store the encrypted secret
	dbSecret, err := s.queries.CreateSecret(ctx, db.CreateSecretParams{
		ProjectID:      projectID,
		Key:            key,
		EncryptedValue: encryptedValue,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	return &Secret{
		ID:        dbSecret.ID,
		ProjectID: dbSecret.ProjectID,
		Key:       dbSecret.Key,
		Version:   dbSecret.Version,
		CreatedAt: dbSecret.CreatedAt,
		UpdatedAt: dbSecret.UpdatedAt,
	}, nil
}

// Get retrieves a secret by key and decrypts its value.
func (s *SecretService) Get(ctx context.Context, projectID uuid.UUID, key string) (*SecretWithValue, error) {
	// Get the encrypted secret
	dbSecret, err := s.queries.GetSecretWithValue(ctx, db.GetSecretWithValueParams{
		ProjectID: projectID,
		Key:       key,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Get the project's DEK
	dek, err := s.projectService.GetDecryptedDEK(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project DEK: %w", err)
	}
	defer crypto.ZeroBytes(dek)

	// Decrypt the value
	value, err := crypto.Decrypt(dek, dbSecret.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return &SecretWithValue{
		Secret: Secret{
			ID:        dbSecret.ID,
			ProjectID: dbSecret.ProjectID,
			Key:       dbSecret.Key,
			Version:   dbSecret.Version,
			CreatedAt: dbSecret.CreatedAt,
			UpdatedAt: dbSecret.UpdatedAt,
		},
		Value: value,
	}, nil
}

// List retrieves all secrets for a project (without values).
func (s *SecretService) List(ctx context.Context, projectID uuid.UUID, limit, offset int32) ([]*Secret, error) {
	dbSecrets, err := s.queries.ListSecretsByProject(ctx, db.ListSecretsByProjectParams{
		ProjectID: projectID,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	secrets := make([]*Secret, len(dbSecrets))
	for i, sec := range dbSecrets {
		secrets[i] = &Secret{
			ID:        sec.ID,
			ProjectID: sec.ProjectID,
			Key:       sec.Key,
			Version:   sec.Version,
			CreatedAt: sec.CreatedAt,
			UpdatedAt: sec.UpdatedAt,
		}
	}

	return secrets, nil
}

// ListKeys retrieves all secret keys for a project.
func (s *SecretService) ListKeys(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	keys, err := s.queries.ListSecretKeysByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret keys: %w", err)
	}
	return keys, nil
}

// Update updates a secret's value.
func (s *SecretService) Update(ctx context.Context, projectID uuid.UUID, key string, value []byte) (*Secret, error) {
	// Get the project's DEK
	dek, err := s.projectService.GetDecryptedDEK(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project DEK: %w", err)
	}
	defer crypto.ZeroBytes(dek)

	// Encrypt the new value
	encryptedValue, err := crypto.Encrypt(dek, value)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Update the secret
	dbSecret, err := s.queries.UpdateSecret(ctx, db.UpdateSecretParams{
		ProjectID:      projectID,
		Key:            key,
		EncryptedValue: encryptedValue,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update secret: %w", err)
	}

	return &Secret{
		ID:        dbSecret.ID,
		ProjectID: dbSecret.ProjectID,
		Key:       dbSecret.Key,
		Version:   dbSecret.Version,
		CreatedAt: dbSecret.CreatedAt,
		UpdatedAt: dbSecret.UpdatedAt,
	}, nil
}

// Upsert creates or updates a secret.
func (s *SecretService) Upsert(ctx context.Context, projectID uuid.UUID, key string, value []byte) (*Secret, error) {
	// Get the project's DEK
	dek, err := s.projectService.GetDecryptedDEK(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project DEK: %w", err)
	}
	defer crypto.ZeroBytes(dek)

	// Encrypt the value
	encryptedValue, err := crypto.Encrypt(dek, value)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Upsert the secret
	dbSecret, err := s.queries.UpsertSecret(ctx, db.UpsertSecretParams{
		ProjectID:      projectID,
		Key:            key,
		EncryptedValue: encryptedValue,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upsert secret: %w", err)
	}

	return &Secret{
		ID:        dbSecret.ID,
		ProjectID: dbSecret.ProjectID,
		Key:       dbSecret.Key,
		Version:   dbSecret.Version,
		CreatedAt: dbSecret.CreatedAt,
		UpdatedAt: dbSecret.UpdatedAt,
	}, nil
}

// Delete removes a secret.
func (s *SecretService) Delete(ctx context.Context, projectID uuid.UUID, key string) error {
	if err := s.queries.DeleteSecret(ctx, db.DeleteSecretParams{
		ProjectID: projectID,
		Key:       key,
	}); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

// Count returns the number of secrets in a project.
func (s *SecretService) Count(ctx context.Context, projectID uuid.UUID) (int64, error) {
	count, err := s.queries.CountSecretsByProject(ctx, projectID)
	if err != nil {
		return 0, fmt.Errorf("failed to count secrets: %w", err)
	}
	return count, nil
}

// CountByOwner returns the total number of secrets across all projects owned by a user.
func (s *SecretService) CountByOwner(ctx context.Context, ownerID uuid.UUID) (int64, error) {
	count, err := s.queries.CountSecretsByOwner(ctx, ownerID)
	if err != nil {
		return 0, fmt.Errorf("failed to count secrets by owner: %w", err)
	}
	return count, nil
}

// GetAll retrieves all secrets with decrypted values for a project.
// Use with caution - only for CLI 'env' command.
func (s *SecretService) GetAll(ctx context.Context, projectID uuid.UUID) (map[string][]byte, error) {
	// Get the project's DEK
	dek, err := s.projectService.GetDecryptedDEK(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project DEK: %w", err)
	}
	defer crypto.ZeroBytes(dek)

	// Get all secret keys
	keys, err := s.queries.ListSecretKeysByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret keys: %w", err)
	}

	secrets := make(map[string][]byte, len(keys))

	for _, key := range keys {
		dbSecret, err := s.queries.GetSecretWithValue(ctx, db.GetSecretWithValueParams{
			ProjectID: projectID,
			Key:       key,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get secret %s: %w", key, err)
		}

		value, err := crypto.Decrypt(dek, dbSecret.EncryptedValue)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", key, err)
		}

		secrets[key] = value
	}

	return secrets, nil
}
