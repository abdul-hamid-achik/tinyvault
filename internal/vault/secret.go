package vault

import (
	"fmt"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/validation"
)

// SetSecret encrypts and stores a secret value under the given project and key.
// If the key already exists, the version is auto-incremented by the store.
func (v *Vault) SetSecret(projectName, key, value string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := v.requireUnlocked(); err != nil {
		return err
	}

	if err := validation.SecretKey(key); err != nil {
		return fmt.Errorf("invalid secret key: %w", err)
	}

	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return mapStoreError(err)
	}

	dek, err := v.getDecryptedDEK(project.ID)
	if err != nil {
		return err
	}

	encryptedValue, err := crypto.Encrypt(dek, []byte(value))
	crypto.ZeroBytes(dek)
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}

	now := time.Now().UTC()
	entry := &store.SecretEntry{
		EncryptedValue: encryptedValue,
		Version:        1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	return mapStoreError(v.store.SetSecret(project.ID, key, entry))
}

// GetSecret decrypts and returns a secret value.
func (v *Vault) GetSecret(projectName, key string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := v.requireUnlocked(); err != nil {
		return "", err
	}

	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return "", mapStoreError(err)
	}

	entry, err := v.store.GetSecret(project.ID, key)
	if err != nil {
		return "", mapStoreError(err)
	}

	dek, err := v.getDecryptedDEK(project.ID)
	if err != nil {
		return "", err
	}

	plaintext, err := crypto.Decrypt(dek, entry.EncryptedValue)
	crypto.ZeroBytes(dek)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}

	return string(plaintext), nil
}

// ListSecrets returns the key names of all secrets in a project.
func (v *Vault) ListSecrets(projectName string) ([]string, error) {
	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return nil, mapStoreError(err)
	}

	keys, err := v.store.ListSecretKeys(project.ID)
	return keys, mapStoreError(err)
}

// DeleteSecret removes a secret by project name and key.
func (v *Vault) DeleteSecret(projectName, key string) error {
	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return mapStoreError(err)
	}

	return mapStoreError(v.store.DeleteSecret(project.ID, key))
}

// GetAllSecrets decrypts and returns all secrets for a project as a map.
func (v *Vault) GetAllSecrets(projectName string) (map[string]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}

	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return nil, mapStoreError(err)
	}

	entries, err := v.store.ListSecrets(project.ID)
	if err != nil {
		return nil, mapStoreError(err)
	}

	dek, err := v.getDecryptedDEK(project.ID)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(dek)

	result := make(map[string]string, len(entries))
	for key, entry := range entries {
		plaintext, err := crypto.Decrypt(dek, entry.EncryptedValue)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret %s: %w", key, err)
		}
		result[key] = string(plaintext)
	}

	return result, nil
}

// SecretMeta is the per-key metadata exposed by ListSecretMetadata.
// Values are intentionally absent: this method is designed for index
// building, search, and listing, where leaking values is undesirable.
type SecretMeta struct {
	Key       string
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ListSecretMetadata returns metadata for every secret in a project
// without decrypting the values. The vault does not need to be
// unlocked; the metadata is stored in the clear alongside the
// ciphertext.
func (v *Vault) ListSecretMetadata(projectName string) ([]SecretMeta, error) {
	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return nil, mapStoreError(err)
	}
	entries, err := v.store.ListSecrets(project.ID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	out := make([]SecretMeta, 0, len(entries))
	for key, entry := range entries {
		out = append(out, SecretMeta{
			Key:       key,
			Version:   entry.Version,
			CreatedAt: entry.CreatedAt,
			UpdatedAt: entry.UpdatedAt,
		})
	}
	return out, nil
}
