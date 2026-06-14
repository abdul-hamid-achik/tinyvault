package cmd

import (
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// TestRunInitHonorsTVAULTPassphrase verifies the non-interactive
// init path: when TVAULT_PASSPHRASE is set, 'tvault init' should
// not prompt and should produce a working vault.
func TestRunInitHonorsTVAULTPassphrase(t *testing.T) {
	dir := t.TempDir()

	// Set the global vault dir.
	oldVaultDir := vaultDir
	defer func() {
		vaultDir = oldVaultDir
	}()
	vaultDir = dir

	// TVAULT_PASSPHRASE is set by setupVaultForCommandTest indirectly
	// via t.Setenv, but we set it explicitly here too for clarity.
	t.Setenv("TVAULT_PASSPHRASE", "test-passphrase")

	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	// The vault should now be openable.
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatalf("vault.Open after init: %v", err)
	}
	defer v.Close()
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

// TestRunInitRejectsExistingVault confirms we don't silently
// overwrite an existing vault.
func TestRunInitRejectsExistingVault(t *testing.T) {
	dir := t.TempDir()

	// Pre-create the vault.
	v, err := vault.Create(dir, "first-passphrase")
	if err != nil {
		t.Fatalf("vault.Create: %v", err)
	}
	v.Close()

	oldVaultDir := vaultDir
	vaultDir = dir
	defer func() { vaultDir = oldVaultDir }()

	t.Setenv("TVAULT_PASSPHRASE", "second-passphrase")

	err = runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error when re-initializing")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error %q should mention 'already exists'", err)
	}

	// The original vault should be untouched.
	v2, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if err := v2.Unlock("first-passphrase"); err != nil {
		t.Errorf("original passphrase should still work: %v", err)
	}
	if err := v2.Unlock("second-passphrase"); err == nil {
		t.Error("second passphrase should NOT work; vault was not overwritten")
	}
}
