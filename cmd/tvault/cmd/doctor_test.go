package cmd

import (
	"os"
	"path/filepath"
	"testing"

	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func withVaultDir(t *testing.T, dir string) {
	t.Helper()
	old, oldJSON := vaultDir, jsonOutput
	t.Cleanup(func() { vaultDir, jsonOutput = old, oldJSON })
	vaultDir, jsonOutput = dir, false
}

func TestDoctorHealthyVaultPasses(t *testing.T) {
	dir := t.TempDir()
	v, err := ivault.Create(dir, "p")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	v.Close()
	withVaultDir(t, dir)
	if err := runDoctor(nil, nil); err != nil {
		t.Errorf("doctor on a healthy vault should pass, got: %v", err)
	}
}

func TestDoctorUninitializedDoesNotFail(t *testing.T) {
	// An uninitialized vault is a warning (not yet set up), not a failure.
	withVaultDir(t, filepath.Join(t.TempDir(), "nope"))
	if err := runDoctor(nil, nil); err != nil {
		t.Errorf("doctor on an uninitialized dir should warn, not fail: %v", err)
	}
}

func TestDoctorMalformedConfigFails(t *testing.T) {
	dir := t.TempDir()
	v, err := ivault.Create(dir, "p")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	v.Close()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("browse: : :\n  bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	withVaultDir(t, dir)
	if err := runDoctor(nil, nil); err == nil {
		t.Error("doctor should fail when config.yaml is malformed")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	withVaultDir(t, dir)

	// Missing file → zero config, no error.
	if c, err := loadConfig(); err != nil || c.Browse.AuditLimit != 0 || c.Browse.NoAnim {
		t.Errorf("missing config: got %+v, err %v", c, err)
	}

	// Valid file → parsed.
	yaml := "browse:\n  no_anim: true\n  single_pane: true\n  audit_limit: 50\n"
	if err := os.WriteFile(configPath(), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !c.Browse.NoAnim || !c.Browse.SinglePane || c.Browse.AuditLimit != 50 {
		t.Errorf("parsed config wrong: %+v", c)
	}

	// Malformed → error.
	if err := os.WriteFile(configPath(), []byte("browse: : :"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil {
		t.Error("malformed config should error")
	}
}
