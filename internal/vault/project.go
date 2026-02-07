package vault

import (
	"fmt"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/validation"
	"github.com/google/uuid"
)

const configCurrentProject = "current_project"

// CreateProject creates a new project with a random DEK encrypted by the vault KEK.
func (v *Vault) CreateProject(name, description string) (*store.Project, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}

	if err := validation.ProjectName(name); err != nil {
		return nil, fmt.Errorf("invalid project name: %w", err)
	}

	if err := validation.ProjectDescription(description); err != nil {
		return nil, fmt.Errorf("invalid description: %w", err)
	}

	// Generate a random DEK for this project.
	dek, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}

	// Encrypt DEK with KEK.
	encryptedDEK, err := crypto.Encrypt(v.kek, dek)
	crypto.ZeroBytes(dek)
	if err != nil {
		return nil, fmt.Errorf("encrypt DEK: %w", err)
	}

	now := time.Now().UTC()
	project := &store.Project{
		ID:           uuid.New(),
		Name:         name,
		Description:  description,
		EncryptedDEK: encryptedDEK,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := v.store.CreateProject(project); err != nil {
		return nil, mapStoreError(err)
	}

	return project, nil
}

// ListProjects returns all non-deleted projects.
func (v *Vault) ListProjects() ([]*store.Project, error) {
	projects, err := v.store.ListProjects()
	return projects, mapStoreError(err)
}

// GetProject retrieves a project by name.
func (v *Vault) GetProject(name string) (*store.Project, error) {
	project, err := v.store.GetProjectByName(name)
	return project, mapStoreError(err)
}

// DeleteProject deletes a project by name.
func (v *Vault) DeleteProject(name string) error {
	project, err := v.store.GetProjectByName(name)
	if err != nil {
		return mapStoreError(err)
	}
	return mapStoreError(v.store.DeleteProject(project.ID))
}

// SetCurrentProject stores the current project name in the vault config.
func (v *Vault) SetCurrentProject(name string) error {
	// Verify the project exists.
	if _, err := v.store.GetProjectByName(name); err != nil {
		return mapStoreError(err)
	}
	return v.store.SetConfig(configCurrentProject, name)
}

// GetCurrentProject reads the current project name from config.
func (v *Vault) GetCurrentProject() (string, error) {
	name, err := v.store.GetConfig(configCurrentProject)
	if err != nil {
		return "", mapStoreError(err)
	}
	return name, nil
}

// getDecryptedDEK decrypts the project DEK using the vault KEK.
// The caller must hold at least an RLock and ensure the vault is unlocked.
// The caller is responsible for zeroing the returned DEK.
func (v *Vault) getDecryptedDEK(projectID uuid.UUID) ([]byte, error) {
	project, err := v.store.GetProject(projectID)
	if err != nil {
		return nil, mapStoreError(err)
	}

	dek, err := crypto.Decrypt(v.kek, project.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("decrypt DEK: %w", err)
	}

	return dek, nil
}
