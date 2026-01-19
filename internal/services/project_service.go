package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/database/db"
)

// ErrDuplicateProjectName is returned when a project name already exists for the user
var ErrDuplicateProjectName = errors.New("a project with this name already exists")

// ProjectService handles project-related business logic.
type ProjectService struct {
	queries   *db.Queries
	pool      *pgxpool.Pool
	masterKey []byte
}

// NewProjectService creates a new ProjectService.
func NewProjectService(pool *pgxpool.Pool, masterKey []byte) *ProjectService {
	return &ProjectService{
		queries:   db.New(pool),
		pool:      pool,
		masterKey: masterKey,
	}
}

// Project represents a TinyVault project.
type Project struct {
	ID          uuid.UUID `json:"id"`
	OwnerID     uuid.UUID `json:"owner_id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Create creates a new project with a new Data Encryption Key.
func (s *ProjectService) Create(ctx context.Context, ownerID uuid.UUID, name, description string) (*Project, error) {
	// Generate a new DEK for this project
	dek, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt the DEK with the master key
	encryptedDEK, err := crypto.Encrypt(s.masterKey, dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Zero out the plaintext DEK
	defer crypto.ZeroBytes(dek)

	var desc *string
	if description != "" {
		desc = &description
	}

	dbProject, err := s.queries.CreateProject(ctx, db.CreateProjectParams{
		OwnerID:      ownerID,
		Name:         name,
		Description:  desc,
		EncryptedDek: encryptedDEK,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateProjectName
		}
		return nil, fmt.Errorf("failed to create project: %w", err)
	}

	return &Project{
		ID:          dbProject.ID,
		OwnerID:     dbProject.OwnerID,
		Name:        dbProject.Name,
		Description: dbProject.Description,
		CreatedAt:   dbProject.CreatedAt,
		UpdatedAt:   dbProject.UpdatedAt,
	}, nil
}

// GetByID retrieves a project by ID.
func (s *ProjectService) GetByID(ctx context.Context, id uuid.UUID) (*Project, error) {
	dbProject, err := s.queries.GetProjectByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %w", err)
	}

	return &Project{
		ID:          dbProject.ID,
		OwnerID:     dbProject.OwnerID,
		Name:        dbProject.Name,
		Description: dbProject.Description,
		CreatedAt:   dbProject.CreatedAt,
		UpdatedAt:   dbProject.UpdatedAt,
	}, nil
}

// GetByIDWithOwner retrieves a project by ID, ensuring it belongs to the owner.
func (s *ProjectService) GetByIDWithOwner(ctx context.Context, id, ownerID uuid.UUID) (*Project, error) {
	dbProject, err := s.queries.GetProjectByIDWithOwner(ctx, db.GetProjectByIDWithOwnerParams{
		ID:      id,
		OwnerID: ownerID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %w", err)
	}

	return &Project{
		ID:          dbProject.ID,
		OwnerID:     dbProject.OwnerID,
		Name:        dbProject.Name,
		Description: dbProject.Description,
		CreatedAt:   dbProject.CreatedAt,
		UpdatedAt:   dbProject.UpdatedAt,
	}, nil
}

// List retrieves all projects for an owner.
func (s *ProjectService) List(ctx context.Context, ownerID uuid.UUID, limit, offset int32) ([]*Project, error) {
	dbProjects, err := s.queries.ListProjectsByOwner(ctx, db.ListProjectsByOwnerParams{
		OwnerID: ownerID,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	projects := make([]*Project, len(dbProjects))
	for i, p := range dbProjects {
		projects[i] = &Project{
			ID:          p.ID,
			OwnerID:     p.OwnerID,
			Name:        p.Name,
			Description: p.Description,
			CreatedAt:   p.CreatedAt,
			UpdatedAt:   p.UpdatedAt,
		}
	}

	return projects, nil
}

// Update updates a project's name and description.
func (s *ProjectService) Update(ctx context.Context, id uuid.UUID, name, description string) (*Project, error) {
	var desc *string
	if description != "" {
		desc = &description
	}

	dbProject, err := s.queries.UpdateProject(ctx, db.UpdateProjectParams{
		ID:          id,
		Name:        name,
		Description: desc,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update project: %w", err)
	}

	return &Project{
		ID:          dbProject.ID,
		OwnerID:     dbProject.OwnerID,
		Name:        dbProject.Name,
		Description: dbProject.Description,
		CreatedAt:   dbProject.CreatedAt,
		UpdatedAt:   dbProject.UpdatedAt,
	}, nil
}

// Delete soft-deletes a project.
func (s *ProjectService) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.queries.SoftDeleteProject(ctx, id); err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}
	return nil
}

// GetDecryptedDEK retrieves and decrypts the DEK for a project.
func (s *ProjectService) GetDecryptedDEK(ctx context.Context, projectID uuid.UUID) ([]byte, error) {
	encryptedDEK, err := s.queries.GetProjectDEK(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project DEK: %w", err)
	}

	dek, err := crypto.Decrypt(s.masterKey, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	return dek, nil
}

// Count returns the number of projects for an owner.
func (s *ProjectService) Count(ctx context.Context, ownerID uuid.UUID) (int64, error) {
	count, err := s.queries.CountProjectsByOwner(ctx, ownerID)
	if err != nil {
		return 0, fmt.Errorf("failed to count projects: %w", err)
	}
	return count, nil
}
