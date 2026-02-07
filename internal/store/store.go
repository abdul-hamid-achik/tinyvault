package store

import "github.com/google/uuid"

// Store defines the interface for vault storage operations.
type Store interface {
	// Vault metadata
	GetMeta() (*VaultMeta, error)
	SetMeta(meta *VaultMeta) error

	// Config
	GetConfig(key string) (string, error)
	SetConfig(key, value string) error

	// Projects
	CreateProject(project *Project) error
	GetProject(id uuid.UUID) (*Project, error)
	GetProjectByName(name string) (*Project, error)
	ListProjects() ([]*Project, error)
	UpdateProject(project *Project) error
	DeleteProject(id uuid.UUID) error

	// Secrets
	SetSecret(projectID uuid.UUID, key string, entry *SecretEntry) error
	GetSecret(projectID uuid.UUID, key string) (*SecretEntry, error)
	ListSecretKeys(projectID uuid.UUID) ([]string, error)
	ListSecrets(projectID uuid.UUID) (map[string]*SecretEntry, error)
	DeleteSecret(projectID uuid.UUID, key string) error

	// Audit
	AppendAudit(entry *AuditEntry) error
	ListAudit(limit int) ([]*AuditEntry, error)

	// Lifecycle
	Close() error
}
