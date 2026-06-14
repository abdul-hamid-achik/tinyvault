package vault

import (
	"bytes"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/store"
)

// Asymmetric sharing (Spine A). A project's DEK can be additionally wrapped
// to X25519 recipients (alongside the KEK wrap the owner uses), so a holder
// of the matching private key can decrypt the project WITHOUT the vault
// passphrase. Revoking a recipient rotates the DEK and re-encrypts every
// value, so a removed recipient (who still holds the old DEK) loses access.

// ShareProject grants the recipient (an X25519 public key) access to a
// project by wrapping the project DEK to it. Requires the vault unlocked
// (the DEK is unwrapped from the KEK to be re-wrapped). Re-sharing with an
// existing recipient refreshes its wrap.
func (v *Vault) ShareProject(name string, recipientPub []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	if len(recipientPub) != crypto.X25519KeySize {
		return fmt.Errorf("invalid recipient key length")
	}
	project, err := v.store.GetProjectByName(name)
	if err != nil {
		return mapStoreError(err)
	}
	dek, err := v.getDecryptedDEK(project.ID)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(dek)

	stanzas, err := crypto.WrapDEK(dek, [][]byte{recipientPub})
	if err != nil {
		return err
	}
	project.RecipientWraps = upsertWrap(project.RecipientWraps, recipientPub, stanzas[0])
	project.UpdatedAt = time.Now().UTC()
	return mapStoreError(v.store.UpdateProject(project))
}

// UnshareProject revokes a recipient. Because the recipient already holds
// the project DEK, revocation is not a simple unwrap-removal: it rotates the
// DEK, re-encrypts every secret in the project, re-wraps the new DEK under
// the KEK, and re-wraps it to all REMAINING recipients — atomically. The
// removed recipient's old DEK can no longer decrypt anything.
func (v *Vault) UnshareProject(name string, recipientPub []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	project, err := v.store.GetProjectByName(name)
	if err != nil {
		return mapStoreError(err)
	}

	remaining := make([]store.DEKWrap, 0, len(project.RecipientWraps))
	found := false
	for _, w := range project.RecipientWraps {
		if bytes.Equal(w.Recipient, recipientPub) {
			found = true
			continue
		}
		remaining = append(remaining, w)
	}
	if !found {
		return fmt.Errorf("project %q is not shared with that recipient", name)
	}

	oldDEK, err := v.getDecryptedDEK(project.ID)
	if err != nil {
		return err
	}
	newDEK, err := crypto.GenerateKey()
	if err != nil {
		crypto.ZeroBytes(oldDEK)
		return err
	}
	defer crypto.ZeroBytes(newDEK)

	// Re-encrypt every value (old DEK -> new DEK), then the archived version
	// history too — or a rollback to a pre-revocation version would be
	// undecryptable under the rotated DEK. Version/timestamps are preserved.
	reEncrypted, err := v.reEncryptCurrentSecrets(project.ID, oldDEK, newDEK)
	if err != nil {
		crypto.ZeroBytes(oldDEK)
		return err
	}
	reEncHistory, err := v.reEncryptHistory(project.ID, oldDEK, newDEK)
	if err != nil {
		crypto.ZeroBytes(oldDEK)
		return err
	}
	crypto.ZeroBytes(oldDEK)

	// Wrap the new DEK under the KEK (owner) and re-wrap to remaining
	// recipients — their old stanzas wrapped the OLD DEK and are now stale.
	newEncDEK, err := crypto.Encrypt(v.kek, newDEK)
	if err != nil {
		return err
	}
	rewrapped := make([]store.DEKWrap, 0, len(remaining))
	for _, w := range remaining {
		stanzas, werr := crypto.WrapDEK(newDEK, [][]byte{w.Recipient})
		if werr != nil {
			return werr
		}
		rewrapped = append(rewrapped, store.DEKWrap{Recipient: w.Recipient, Stanza: stanzas[0]})
	}

	project.EncryptedDEK = newEncDEK
	project.RecipientWraps = rewrapped
	project.UpdatedAt = time.Now().UTC()
	return mapStoreError(v.store.RekeyProject(project, reEncrypted, reEncHistory))
}

// reEncryptCurrentSecrets decrypts every current secret with oldDEK and
// re-encrypts it with newDEK, returning the rewritten map for RekeyProject.
func (v *Vault) reEncryptCurrentSecrets(projectID uuid.UUID, oldDEK, newDEK []byte) (map[string]*store.SecretEntry, error) {
	entries, err := v.store.ListSecrets(projectID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	out := make(map[string]*store.SecretEntry, len(entries))
	for key, e := range entries {
		pt, derr := crypto.Decrypt(oldDEK, e.EncryptedValue)
		if derr != nil {
			return nil, fmt.Errorf("rekey: decrypt %s: %w", key, derr)
		}
		ct, eerr := crypto.Encrypt(newDEK, pt)
		crypto.ZeroBytes(pt)
		if eerr != nil {
			return nil, fmt.Errorf("rekey: re-encrypt %s: %w", key, eerr)
		}
		e.EncryptedValue = ct
		out[key] = e
	}
	return out, nil
}

// reEncryptHistory decrypts every archived secret version with oldDEK and
// re-encrypts it with newDEK, returning the rewritten history for RekeyProject.
// It maps store errors but otherwise leaves DEK lifecycle to the caller.
func (v *Vault) reEncryptHistory(projectID uuid.UUID, oldDEK, newDEK []byte) ([]store.VersionedSecret, error) {
	entries, err := v.store.ListSecretVersionEntries(projectID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	out := make([]store.VersionedSecret, 0, len(entries))
	for _, h := range entries {
		pt, derr := crypto.Decrypt(oldDEK, h.Entry.EncryptedValue)
		if derr != nil {
			return nil, fmt.Errorf("rekey history: decrypt %s v%d: %w", h.Key, h.Entry.Version, derr)
		}
		ct, eerr := crypto.Encrypt(newDEK, pt)
		crypto.ZeroBytes(pt)
		if eerr != nil {
			return nil, fmt.Errorf("rekey history: re-encrypt %s v%d: %w", h.Key, h.Entry.Version, eerr)
		}
		h.Entry.EncryptedValue = ct
		out = append(out, h)
	}
	return out, nil
}

// ProjectRecipients returns the X25519 public keys a project is shared with.
func (v *Vault) ProjectRecipients(name string) ([][]byte, error) {
	project, err := v.store.GetProjectByName(name)
	if err != nil {
		return nil, mapStoreError(err)
	}
	out := make([][]byte, 0, len(project.RecipientWraps))
	for _, w := range project.RecipientWraps {
		out = append(out, w.Recipient)
	}
	return out, nil
}

// GetAllSecretsWithIdentity decrypts every secret in a project using an
// X25519 identity instead of the passphrase. This is the recipient-read
// path: a holder of a shared identity can read the project from the vault
// file WITHOUT unlocking it (no KEK involved). Returns
// crypto.ErrNoMatchingRecipient if the identity was not granted access.
func (v *Vault) GetAllSecretsWithIdentity(name string, id *crypto.Identity) (map[string]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	project, err := v.store.GetProjectByName(name)
	if err != nil {
		return nil, mapStoreError(err)
	}
	if len(project.RecipientWraps) == 0 {
		return nil, fmt.Errorf("project %q is not shared with any recipient", name)
	}
	stanzas := make([][]byte, 0, len(project.RecipientWraps))
	for _, w := range project.RecipientWraps {
		stanzas = append(stanzas, w.Stanza)
	}
	dek, err := crypto.UnwrapDEK(id, stanzas)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(dek)

	entries, err := v.store.ListSecrets(project.ID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	result := make(map[string]string, len(entries))
	for key, e := range entries {
		pt, derr := crypto.Decrypt(dek, e.EncryptedValue)
		if derr != nil {
			return nil, fmt.Errorf("decrypt %s: %w", key, derr)
		}
		result[key] = string(pt)
	}
	return result, nil
}

// upsertWrap replaces the wrap for recipient if present, else appends it.
func upsertWrap(wraps []store.DEKWrap, recipient, stanza []byte) []store.DEKWrap {
	for i := range wraps {
		if bytes.Equal(wraps[i].Recipient, recipient) {
			wraps[i].Stanza = stanza
			return wraps
		}
	}
	return append(wraps, store.DEKWrap{Recipient: recipient, Stanza: stanza})
}
