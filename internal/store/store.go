// Package store is the persistence layer for TinyVault.
//
// # Design
//
// The store is a SQL-shaped tabular API on top of a bbolt key-value
// engine. The bbolt file is the only on-disk artifact; there is no
// separate search index, no derived file, no schema migration tool.
//
// We deliberately do not use SQLite or a relational engine here:
//
//   - The vault is a single-process, single-user artifact. bbolt's
//     flock-based concurrency and embedded mmap are exactly the right
//     fit. SQLite's WAL, query planner, and schema migrations solve
//     problems we do not have.
//   - The encryption layer must be auditable. With bbolt, the
//     encrypt/decrypt calls are adjacent to the read/write calls in
//     the same file. With a SQL engine + generated code, the data
//     path is split across a schema, generated Go, and a runtime
//     that an auditor has to read separately.
//   - Supply-chain surface is smaller with bbolt. modernc.org/sqlite
//     is a fine library but is a larger attack surface for code that
//     handles plaintext secret values.
//
// # SQL-shaped API
//
// The store exposes a tabular API: Project, SecretEntry, and
// AuditEntry are first-class rows with explicit columns, not opaque
// blobs. Operations are typed. Relational queries (prefix scan,
// time range, name glob, by project) are first-class methods on the
// store, not string-template SQL.
//
// This gives callers the ergonomics of a relational store without
// paying for a relational engine. A future backend (Postgres,
// encrypted SQL, etc.) can be slotted in by implementing Store.
//
// # Search
//
// Search is done by iterating the bbolt cursor and filtering in Go.
// The filter is applied to the *metadata* of each row only:
// SecretEntry.EncryptedValue is never decrypted during a search.
// The cost is O(N) over keys + project names, which is fine for the
// expected scale (hundreds to low thousands of secrets per vault).
// For a local-first single-user tool, this is the right trade-off.
package store

import (
	"time"

	"github.com/google/uuid"
)

// Store is the persistence layer for TinyVault.
//
// All methods are safe for concurrent use by a single process.
// Cross-process access is not supported.
type Store interface {
	// Meta is the per-vault metadata (one row: "vault_meta").
	MetaStore
	// Config holds key/value vault config (current project, etc.).
	ConfigStore
	// Projects is the projects table.
	ProjectStore
	// Secrets is the secrets table (per-project DEK + ciphertext).
	SecretStore
	// Audit is the append-only audit log.
	AuditStore
	// Close releases the underlying file handle.
	Close() error
}

// MetaStore holds the per-vault metadata. There is exactly one row.
type MetaStore interface {
	GetMeta() (*VaultMeta, error)
	SetMeta(meta *VaultMeta) error
}

// ConfigStore is a small key/value table for vault config.
type ConfigStore interface {
	GetConfig(key string) (string, error)
	SetConfig(key, value string) error
	DeleteConfig(key string) error
}

// ProjectStore is the projects table.
type ProjectStore interface {
	// CreateProject inserts a new project. Returns
	// ErrDuplicateProjectName if a project with the same name already
	// exists (including soft-deleted projects whose name index has
	// not been cleared).
	CreateProject(project *Project) error

	// GetProject retrieves a project by its UUID.
	GetProject(id uuid.UUID) (*Project, error)

	// GetProjectByName retrieves a project by name using the name
	// index.
	GetProjectByName(name string) (*Project, error)

	// ListProjects returns all non-deleted projects, sorted by name.
	ListProjects() ([]*Project, error)

	// ListProjectsIncludingDeleted returns every project, including
	// soft-deleted ones. Used by recovery / upgrade tooling.
	ListProjectsIncludingDeleted() ([]*Project, error)

	// UpdateProject updates an existing project in place. Renames
	// are reflected in the name index atomically.
	UpdateProject(project *Project) error

	// DeleteProject soft-deletes by setting DeletedAt; clears the
	// name index entry so the name can be reused.
	DeleteProject(id uuid.UUID) error

	// ProjectFilter narrows the result set.
	// A zero-value ProjectFilter means "no filter".
	ListProjectsFiltered(filter ProjectFilter) ([]*Project, error)

	// RekeyProject atomically replaces a project's record AND rewrites all
	// of its secret entries (verbatim, no version bump) in a single
	// transaction. Used when revoking a recipient: the DEK is rotated and
	// every value re-encrypted, which must be all-or-nothing so a failure
	// can never leave secrets encrypted under a mix of old and new keys.
	RekeyProject(project *Project, secrets map[string]*SecretEntry) error
}

// ProjectFilter narrows a ListProjects call.
//
// NameLike applies a SQL-style LIKE pattern (only '*' wildcard is
// supported) against the project name. DescriptionLike works the
// same way against the description.
type ProjectFilter struct {
	NameLike        string
	DescriptionLike string
	Limit           int
	Offset          int
}

// SecretStore is the secrets table.
//
// Secret rows are keyed by (project_id, key). The composite key is
// materialized as a single bbolt key: projectID.String() + "/" + key.
type SecretStore interface {
	// SetSecret inserts or updates a secret. If the key already
	// exists, the version is auto-incremented (upsert semantics).
	SetSecret(projectID uuid.UUID, key string, entry *SecretEntry) error

	// GetSecret retrieves a single secret by project and key.
	GetSecret(projectID uuid.UUID, key string) (*SecretEntry, error)

	// DeleteSecret removes a secret by project and key.
	DeleteSecret(projectID uuid.UUID, key string) error

	// ListSecretKeys returns just the secret key names for a project.
	ListSecretKeys(projectID uuid.UUID) ([]string, error)

	// ListSecrets returns every secret (full row) for a project.
	ListSecrets(projectID uuid.UUID) (map[string]*SecretEntry, error)

	// ListSecretKeysFiltered returns keys matching the filter.
	// Used by `tvault list --prefix STRIPE_` and similar.
	ListSecretKeysFiltered(projectID uuid.UUID, filter SecretFilter) ([]string, error)

	// ListSecretsByProject returns every (projectID, key) pair
	// across all projects, filtered. Used by MCP "list everything
	// matching X" calls and by the agent-discoverability layer.
	ListSecretsByProject(filter SecretFilter) ([]SecretLocation, error)

	// CountSecrets returns the number of secrets in a project.
	CountSecrets(projectID uuid.UUID) (int, error)
}

// SecretFilter narrows secret listings.
//
// Prefix:        only keys starting with this string (no wildcard).
// NameLike:      SQL-style LIKE pattern with '*' wildcard.
// UpdatedAfter:  only secrets whose UpdatedAt is >= this time.
// UpdatedBefore: only secrets whose UpdatedAt is <= this time.
// VersionAtLeast: only secrets whose Version >= this value.
// Limit / Offset: pagination. Limit <= 0 means 1000 (default).
type SecretFilter struct {
	Prefix         string
	NameLike       string
	UpdatedAfter   time.Time
	UpdatedBefore  time.Time
	VersionAtLeast int
	Limit          int
	Offset         int
}

// SecretLocation identifies a single secret row by (project, key).
// It is what ListSecretsByProject returns.
type SecretLocation struct {
	ProjectID   uuid.UUID
	ProjectName string
	Key         string
	Version     int
	UpdatedAt   time.Time
}

// AuditStore is the append-only audit log.
type AuditStore interface {
	// AppendAudit inserts an audit row.
	AppendAudit(entry *AuditEntry) error

	// ListAudit returns the most recent entries (newest first) up
	// to limit. limit <= 0 means 100.
	ListAudit(limit int) ([]*AuditEntry, error)

	// ListAuditFiltered returns entries matching the filter, newest
	// first.
	ListAuditFiltered(filter AuditFilter) ([]*AuditEntry, error)

	// CountAudit returns the total number of audit entries.
	CountAudit() (int, error)
}

// AuditFilter narrows audit listings.
//
// Action:        only entries whose Action equals this string (exact).
// ResourceType:  only entries whose ResourceType equals this string.
// Since:         only entries whose Timestamp >= this time.
// Until:         only entries whose Timestamp <= this time.
// Limit / Offset: pagination.
type AuditFilter struct {
	Action       string
	ResourceType string
	Since        time.Time
	Until        time.Time
	Limit        int
	Offset       int
}

// VaultMeta holds vault-level metadata.
type VaultMeta struct {
	Version   int       `json:"version"`
	Salt      []byte    `json:"salt"`
	Verifier  []byte    `json:"verifier"`
	CreatedAt time.Time `json:"created_at"`
	VaultID   string    `json:"vault_id"`
}

// Argon2Params holds the parameters for Argon2id key derivation.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

// Project represents a local vault project.
type Project struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description,omitempty"`
	EncryptedDEK []byte     `json:"encrypted_dek"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`

	// RecipientWraps holds the project DEK additionally wrapped to one or
	// more X25519 recipients (the asymmetric sharing layer). It is absent on
	// projects that have never been shared (backward-compatible: old records
	// deserialize to nil). The DEK is still wrapped under the vault KEK in
	// EncryptedDEK for the local owner; these are extra copies for sharing.
	RecipientWraps []DEKWrap `json:"recipient_wraps,omitempty"`
}

// DEKWrap is one project-DEK copy wrapped to a single X25519 recipient.
type DEKWrap struct {
	Recipient []byte `json:"recipient"` // X25519 public key (the recipient)
	Stanza    []byte `json:"stanza"`    // crypto.WrapDEK output for that recipient
}

// SecretEntry represents an encrypted secret stored in the vault.
//
// EncryptedValue is the AES-256-GCM ciphertext (nonce || ct || tag)
// produced by the project's DEK. The Version field tracks the
// number of times this row has been overwritten.
type SecretEntry struct {
	EncryptedValue []byte    `json:"encrypted_value"`
	Version        int       `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AuditEntry represents a local audit log entry.
type AuditEntry struct {
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id,omitempty"`
	ResourceName string         `json:"resource_name,omitempty"`
	Timestamp    time.Time      `json:"timestamp"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}
