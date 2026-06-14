package cmd

import (
	"path/filepath"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func TestProjectShareReadUnshareCLI(t *testing.T) {
	dir := t.TempDir()
	v, err := ivault.Create(dir, "p")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := v.SetSecret("default", "API_KEY", "sk_live"); err != nil {
		t.Fatalf("set: %v", err)
	}
	v.Close()

	oldVaultDir, oldProject, oldJSON, oldIdent := vaultDir, projectName, jsonOutput, envIdentity
	t.Cleanup(func() {
		vaultDir, projectName, jsonOutput, envIdentity = oldVaultDir, oldProject, oldJSON, oldIdent
	})
	vaultDir, projectName, jsonOutput, envIdentity = dir, "", false, ""
	t.Setenv("TVAULT_PASSPHRASE", "p")

	if err := runIdentityNew(nil, []string{"alice"}); err != nil {
		t.Fatalf("identity new: %v", err)
	}
	id, err := loadIdentity(filepath.Join(identitiesDir(), "alice.key"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	recipient := crypto.EncodeRecipient(id.Recipient())

	// Invalid recipient string is rejected.
	if err := runProjectShare(nil, []string{"not-a-recipient"}); err == nil {
		t.Error("sharing with a garbage recipient should fail")
	}

	// Share, then the recipient reads WITHOUT the passphrase.
	if err := runProjectShare(nil, []string{recipient}); err != nil {
		t.Fatalf("share: %v", err)
	}
	envIdentity = "alice"
	secrets, err := envSecrets()
	if err != nil {
		t.Fatalf("identity read: %v", err)
	}
	if secrets["API_KEY"] != "sk_live" {
		t.Errorf("recipient read wrong value: %v", secrets)
	}
	envIdentity = ""

	if err := runProjectRecipients(nil, nil); err != nil {
		t.Errorf("recipients: %v", err)
	}

	// Unshare → the recipient can no longer read.
	if err := runProjectUnshare(nil, []string{recipient}); err != nil {
		t.Fatalf("unshare: %v", err)
	}
	envIdentity = "alice"
	if _, err := envSecrets(); err == nil {
		t.Error("revoked recipient should no longer read")
	}
	envIdentity = ""

	// Unsharing a non-recipient errors.
	if err := runProjectUnshare(nil, []string{recipient}); err == nil {
		t.Error("unsharing an already-revoked recipient should fail")
	}
}
