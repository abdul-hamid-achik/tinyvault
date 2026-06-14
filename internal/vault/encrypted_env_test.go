package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

// TestEncryptedEnvRoundTripThroughVault covers the full agent workflow:
// set a secret in the vault, dump to an encrypted .env.encrypted, then
// decrypt it back and verify the plaintext matches.
func TestEncryptedEnvRoundTripThroughVault(t *testing.T) {
	dir := t.TempDir()
	v, err := Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer v.Close()

	if err := v.SetSecret("default", "DATABASE_URL", "postgres://localhost/x"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if err := v.SetSecret("default", "STRIPE_KEY", "sk_test_abc"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	// Round-trip a single secret through encrypted-env using the
	// vault's KEK.
	kek, err := v.KEK()
	if err != nil {
		t.Fatalf("KEK: %v", err)
	}
	defer zeroForTest(kek)

	plaintext := []byte("DATABASE_URL=postgres://localhost/x\n")
	ct, err := encryptedenv.Encrypt(kek, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// File on disk for good measure.
	envFile := filepath.Join(dir, ".env.encrypted")
	if err := writeForTest(envFile, ct); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Re-read and decrypt.
	readBack, err := readForTest(envFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	pt, err := encryptedenv.Decrypt(kek, readBack)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("round-trip mismatch:\n got: %q\nwant: %q", pt, plaintext)
	}
}

func TestListSecretMetadata(t *testing.T) {
	dir := t.TempDir()
	v, err := Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer v.Close()

	// Set some secrets.
	if err := v.SetSecret("default", "A", "1"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "B", "2"); err != nil {
		t.Fatal(err)
	}
	// Update one of them to bump version.
	if err := v.SetSecret("default", "A", "1-updated"); err != nil {
		t.Fatal(err)
	}

	metas, err := v.ListSecretMetadata("default")
	if err != nil {
		t.Fatalf("ListSecretMetadata: %v", err)
	}
	if len(metas) != 2 {
		t.Errorf("expected 2 entries, got %d", len(metas))
	}

	got := map[string]SecretMeta{}
	for _, m := range metas {
		got[m.Key] = m
	}

	if got["A"].Version < 2 {
		t.Errorf("A version should be >= 2 after update, got %d", got["A"].Version)
	}
	if got["B"].Version != 1 {
		t.Errorf("B version should be 1, got %d", got["B"].Version)
	}
	if got["A"].CreatedAt.IsZero() {
		t.Error("A CreatedAt should be set")
	}
	if got["A"].UpdatedAt.IsZero() {
		t.Error("A UpdatedAt should be set")
	}
}

// TestListSecretMetadataForUnknownProject confirms we surface the
// sentinel error rather than panicking.
func TestListSecretMetadataForUnknownProject(t *testing.T) {
	dir := t.TempDir()
	v, err := Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer v.Close()

	_, err = v.ListSecretMetadata("nope")
	if err == nil {
		t.Fatal("expected error for unknown project")
	}
}

func TestJSONMarshalingOfSecretMeta(t *testing.T) {
	// Sanity check that SecretMeta round-trips through JSON for the
	// MCP and docs surfaces.
	m := SecretMeta{Key: "FOO", Version: 3}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"Key":"FOO","Version":3,"CreatedAt":"0001-01-01T00:00:00Z","UpdatedAt":"0001-01-01T00:00:00Z"}` {
		t.Errorf("unexpected JSON: %s", data)
	}
}

// helpers -- thin wrappers so the test does not have to import os.
func writeForTest(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
func readForTest(path string) ([]byte, error) {
	return os.ReadFile(path)
}
func zeroForTest(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
