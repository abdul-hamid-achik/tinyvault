package vault

import (
	"errors"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

func sharingVault(t *testing.T) *Vault {
	t.Helper()
	v, err := Create(t.TempDir(), "owner-pass")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	for k, val := range map[string]string{"DB_URL": "postgres://x", "API_KEY": "sk_123"} {
		if err := v.SetSecret("default", k, val); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	return v
}

func TestShareAndRecipientRead(t *testing.T) {
	v := sharingVault(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	outsider, _ := crypto.GenerateIdentity()

	if err := v.ShareProject("default", alice.Recipient()); err != nil {
		t.Fatalf("share alice: %v", err)
	}
	if err := v.ShareProject("default", bob.Recipient()); err != nil {
		t.Fatalf("share bob: %v", err)
	}

	// Both recipients can read every secret, without the passphrase.
	for name, id := range map[string]*crypto.Identity{"alice": alice, "bob": bob} {
		got, err := v.GetAllSecretsWithIdentity("default", id)
		if err != nil {
			t.Fatalf("%s read: %v", name, err)
		}
		if got["DB_URL"] != "postgres://x" || got["API_KEY"] != "sk_123" {
			t.Errorf("%s got wrong secrets: %v", name, got)
		}
	}
	// An outsider cannot.
	if _, err := v.GetAllSecretsWithIdentity("default", outsider); !errors.Is(err, crypto.ErrNoMatchingRecipient) {
		t.Errorf("outsider read should fail, got %v", err)
	}

	recips, _ := v.ProjectRecipients("default")
	if len(recips) != 2 {
		t.Errorf("want 2 recipients, got %d", len(recips))
	}
}

func TestUnshareRotatesAndRevokes(t *testing.T) {
	v := sharingVault(t)
	// Bump API_KEY to version 2 to verify versions survive the re-key.
	if err := v.SetSecret("default", "API_KEY", "sk_v2"); err != nil {
		t.Fatal(err)
	}
	verBefore := secretVersion(t, v, "API_KEY")

	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	mustShare(t, v, alice, bob)

	if err := v.UnshareProject("default", bob.Recipient()); err != nil {
		t.Fatalf("unshare bob: %v", err)
	}

	// Bob can no longer read the updated live vault: its DEK was rotated and
	// its current values were re-encrypted. A pre-removal snapshot would remain
	// readable under the old DEK.
	if _, err := v.GetAllSecretsWithIdentity("default", bob); !errors.Is(err, crypto.ErrNoMatchingRecipient) {
		t.Errorf("removed bob should not read the updated live vault, got %v", err)
	}
	// Alice (still shared) can read, with values intact.
	got, err := v.GetAllSecretsWithIdentity("default", alice)
	if err != nil {
		t.Fatalf("alice read after unshare: %v", err)
	}
	if got["API_KEY"] != "sk_v2" || got["DB_URL"] != "postgres://x" {
		t.Errorf("values changed by re-key: %v", got)
	}
	// The owner (passphrase path) still reads everything.
	ownerGot, err := v.GetAllSecrets("default")
	if err != nil || ownerGot["API_KEY"] != "sk_v2" {
		t.Errorf("owner read after unshare failed: %v / %v", ownerGot, err)
	}
	// Versions preserved through the re-key (it's a re-encryption, not an edit).
	if v2 := secretVersion(t, v, "API_KEY"); v2 != verBefore {
		t.Errorf("version changed by re-key: %d -> %d", verBefore, v2)
	}
	// Only alice remains.
	if recips, _ := v.ProjectRecipients("default"); len(recips) != 1 {
		t.Errorf("want 1 recipient after unshare, got %d", len(recips))
	}
}

func TestUnshareUnknownRecipient(t *testing.T) {
	v := sharingVault(t)
	ghost, _ := crypto.GenerateIdentity()
	if err := v.UnshareProject("default", ghost.Recipient()); err == nil {
		t.Error("unsharing a non-recipient should error")
	}
}

func TestShareRequiresUnlock(t *testing.T) {
	v := sharingVault(t)
	v.Lock()
	id, _ := crypto.GenerateIdentity()
	if err := v.ShareProject("default", id.Recipient()); !errors.Is(err, ErrLocked) {
		t.Errorf("share on locked vault should return ErrLocked, got %v", err)
	}
}

func mustShare(t *testing.T, v *Vault, ids ...*crypto.Identity) {
	t.Helper()
	for _, id := range ids {
		if err := v.ShareProject("default", id.Recipient()); err != nil {
			t.Fatalf("share: %v", err)
		}
	}
}

func secretVersion(t *testing.T, v *Vault, key string) int {
	t.Helper()
	metas, err := v.ListSecretMetadata("default")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	for _, m := range metas {
		if m.Key == key {
			return m.Version
		}
	}
	t.Fatalf("key %s not found", key)
	return 0
}
