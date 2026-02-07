// Package vault provides high-level vault operations that orchestrate
// cryptographic operations and persistent storage.
package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/google/uuid"
)

const (
	dbFilename = "vault.db"
	verifyText = "tinyvault-verify-v1"
)

// Vault orchestrates crypto and store operations.
type Vault struct {
	store store.Store
	kek   []byte // master key encryption key; nil when locked
	path  string // vault directory path
	mu    sync.RWMutex
}

// Create initializes a new vault in the given directory.
// The directory is created with 0700 permissions. A default project is
// automatically created. The returned vault is open and unlocked.
func Create(dir, passphrase string) (*Vault, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	kek, err := crypto.DeriveKey([]byte(passphrase), salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	verifier, err := crypto.Encrypt(kek, []byte(verifyText))
	if err != nil {
		crypto.ZeroBytes(kek)
		return nil, fmt.Errorf("create verifier: %w", err)
	}

	dbPath := filepath.Join(dir, dbFilename)
	s, err := store.NewBoltStore(dbPath)
	if err != nil {
		crypto.ZeroBytes(kek)
		return nil, fmt.Errorf("open store: %w", err)
	}

	meta := &store.VaultMeta{
		Version:   1,
		Salt:      salt,
		Verifier:  verifier,
		CreatedAt: time.Now().UTC(),
		VaultID:   uuid.New().String(),
	}
	if err := s.SetMeta(meta); err != nil {
		crypto.ZeroBytes(kek)
		s.Close()
		return nil, fmt.Errorf("set meta: %w", err)
	}

	v := &Vault{
		store: s,
		kek:   kek,
		path:  dir,
	}

	// Create default project.
	if _, err := v.CreateProject("default", "Default project"); err != nil {
		v.Close()
		return nil, fmt.Errorf("create default project: %w", err)
	}

	// Set default as current project.
	if err := v.SetCurrentProject("default"); err != nil {
		v.Close()
		return nil, fmt.Errorf("set current project: %w", err)
	}

	return v, nil
}

// Open opens an existing vault directory in locked state.
func Open(dir string) (*Vault, error) {
	dbPath := filepath.Join(dir, dbFilename)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, ErrNotInitialized
	}

	s, err := store.NewBoltStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	// Verify it's a valid vault by reading meta.
	if _, err := s.GetMeta(); err != nil {
		s.Close()
		return nil, ErrNotInitialized
	}

	return &Vault{
		store: s,
		kek:   nil,
		path:  dir,
	}, nil
}

// Unlock derives the KEK from the passphrase and verifies it against the
// stored verifier. On success the vault transitions to unlocked state.
func (v *Vault) Unlock(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	meta, err := v.store.GetMeta()
	if err != nil {
		return fmt.Errorf("get meta: %w", err)
	}

	kek, err := crypto.DeriveKey([]byte(passphrase), meta.Salt)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	plaintext, err := crypto.Decrypt(kek, meta.Verifier)
	if err != nil {
		crypto.ZeroBytes(kek)
		return ErrWrongPassphrase
	}

	if string(plaintext) != verifyText {
		crypto.ZeroBytes(kek)
		return ErrWrongPassphrase
	}

	v.kek = kek
	return nil
}

// Lock zeros the KEK and transitions the vault to locked state.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.kek != nil {
		crypto.ZeroBytes(v.kek)
		v.kek = nil
	}
}

// IsUnlocked reports whether the vault is currently unlocked.
func (v *Vault) IsUnlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.kek != nil
}

// Close locks the vault and closes the underlying store.
func (v *Vault) Close() error {
	v.Lock()
	if v.store != nil {
		return v.store.Close()
	}
	return nil
}

// requireUnlocked returns ErrLocked if the vault is not unlocked.
// The caller must hold at least an RLock.
func (v *Vault) requireUnlocked() error {
	if v.kek == nil {
		return ErrLocked
	}
	return nil
}

// RotatePassphrase re-encrypts all project DEKs under a new KEK derived from
// newPassphrase. The old passphrase is verified first.
func (v *Vault) RotatePassphrase(oldPassphrase, newPassphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Verify old passphrase.
	meta, err := v.store.GetMeta()
	if err != nil {
		return fmt.Errorf("get meta: %w", err)
	}

	oldKEK, err := crypto.DeriveKey([]byte(oldPassphrase), meta.Salt)
	if err != nil {
		return fmt.Errorf("derive old key: %w", err)
	}

	plaintext, err := crypto.Decrypt(oldKEK, meta.Verifier)
	if err != nil {
		crypto.ZeroBytes(oldKEK)
		return ErrWrongPassphrase
	}
	if string(plaintext) != verifyText {
		crypto.ZeroBytes(oldKEK)
		return ErrWrongPassphrase
	}

	// Derive new KEK.
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		crypto.ZeroBytes(oldKEK)
		return fmt.Errorf("generate new salt: %w", err)
	}

	newKEK, err := crypto.DeriveKey([]byte(newPassphrase), newSalt)
	if err != nil {
		crypto.ZeroBytes(oldKEK)
		return fmt.Errorf("derive new key: %w", err)
	}

	// Re-encrypt all project DEKs.
	projects, err := v.store.ListProjects()
	if err != nil {
		crypto.ZeroBytes(oldKEK)
		crypto.ZeroBytes(newKEK)
		return fmt.Errorf("list projects: %w", err)
	}

	for _, p := range projects {
		// Decrypt DEK with old KEK.
		dek, err := crypto.Decrypt(oldKEK, p.EncryptedDEK)
		if err != nil {
			crypto.ZeroBytes(oldKEK)
			crypto.ZeroBytes(newKEK)
			return fmt.Errorf("decrypt DEK for project %s: %w", p.Name, err)
		}

		// Re-encrypt DEK with new KEK.
		encDEK, err := crypto.Encrypt(newKEK, dek)
		crypto.ZeroBytes(dek)
		if err != nil {
			crypto.ZeroBytes(oldKEK)
			crypto.ZeroBytes(newKEK)
			return fmt.Errorf("re-encrypt DEK for project %s: %w", p.Name, err)
		}

		p.EncryptedDEK = encDEK
		p.UpdatedAt = time.Now().UTC()
		if err := v.store.UpdateProject(p); err != nil {
			crypto.ZeroBytes(oldKEK)
			crypto.ZeroBytes(newKEK)
			return fmt.Errorf("update project %s: %w", p.Name, err)
		}
	}

	// Create new verifier.
	newVerifier, err := crypto.Encrypt(newKEK, []byte(verifyText))
	if err != nil {
		crypto.ZeroBytes(oldKEK)
		crypto.ZeroBytes(newKEK)
		return fmt.Errorf("create new verifier: %w", err)
	}

	// Update metadata.
	meta.Salt = newSalt
	meta.Verifier = newVerifier
	if err := v.store.SetMeta(meta); err != nil {
		crypto.ZeroBytes(oldKEK)
		crypto.ZeroBytes(newKEK)
		return fmt.Errorf("update meta: %w", err)
	}

	// Swap KEK.
	crypto.ZeroBytes(oldKEK)
	if v.kek != nil {
		crypto.ZeroBytes(v.kek)
	}
	v.kek = newKEK

	return nil
}

// mapStoreError translates store-level sentinel errors to vault-level errors.
func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrProjectNotFound) {
		return ErrProjectNotFound
	}
	if errors.Is(err, store.ErrSecretNotFound) {
		return ErrSecretNotFound
	}
	if errors.Is(err, store.ErrDuplicateProjectName) {
		return ErrProjectExists
	}
	return err
}
