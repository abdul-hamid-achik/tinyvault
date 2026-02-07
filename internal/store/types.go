package store

import (
	"time"

	"github.com/google/uuid"
)

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
}

// SecretEntry represents an encrypted secret stored in the vault.
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
