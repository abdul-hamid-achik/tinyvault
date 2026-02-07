package vault

import (
	"errors"
	"path/filepath"
	"testing"
)

const testPassphrase = "test-passphrase-123"

// helper creates a new vault in a temp directory and returns it with a cleanup.
func createTestVault(t *testing.T) *Vault {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Create vault: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestCreate_NewVault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer v.Close()

	if !v.IsUnlocked() {
		t.Fatal("vault should be unlocked after Create")
	}

	// Default project should exist.
	projects, err := v.ListProjects()
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	if projects[0].Name != "default" {
		t.Fatalf("expected default project, got %q", projects[0].Name)
	}

	// Current project should be "default".
	cur, err := v.GetCurrentProject()
	if err != nil {
		t.Fatalf("GetCurrentProject: %v", err)
	}
	if cur != "default" {
		t.Fatalf("expected current project 'default', got %q", cur)
	}
}

func TestOpen_ExistingVault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	v.Close()

	// Re-open the vault.
	v2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer v2.Close()

	if v2.IsUnlocked() {
		t.Fatal("vault should be locked after Open")
	}
}

func TestOpen_NonExistentDir(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "nonexistent"))
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized, got %v", err)
	}
}

func TestUnlock_CorrectPassphrase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	v.Close()

	v2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer v2.Close()

	if err := v2.Unlock(testPassphrase); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	if !v2.IsUnlocked() {
		t.Fatal("vault should be unlocked after Unlock")
	}
}

func TestUnlock_WrongPassphrase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	v.Close()

	v2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer v2.Close()

	err = v2.Unlock("wrong-passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}

	if v2.IsUnlocked() {
		t.Fatal("vault should remain locked after wrong passphrase")
	}
}

func TestLock_ClearsKey(t *testing.T) {
	v := createTestVault(t)

	if !v.IsUnlocked() {
		t.Fatal("vault should start unlocked")
	}

	v.Lock()

	if v.IsUnlocked() {
		t.Fatal("vault should be locked after Lock")
	}

	// Operations should fail.
	_, err := v.CreateProject("test", "")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestCreateProject(t *testing.T) {
	v := createTestVault(t)

	p, err := v.CreateProject("myproject", "A test project")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	if p.Name != "myproject" {
		t.Fatalf("expected name 'myproject', got %q", p.Name)
	}
	if p.Description != "A test project" {
		t.Fatalf("expected description 'A test project', got %q", p.Description)
	}

	// Should have encrypted DEK.
	if len(p.EncryptedDEK) == 0 {
		t.Fatal("expected non-empty encrypted DEK")
	}

	// Creating a duplicate should fail.
	_, err = v.CreateProject("myproject", "")
	if !errors.Is(err, ErrProjectExists) {
		t.Fatalf("expected ErrProjectExists, got %v", err)
	}
}

func TestSetAndGetSecret(t *testing.T) {
	v := createTestVault(t)

	if err := v.SetSecret("default", "API_KEY", "secret-value-123"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	got, err := v.GetSecret("default", "API_KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}

	if got != "secret-value-123" {
		t.Fatalf("expected 'secret-value-123', got %q", got)
	}
}

func TestSetSecret_VersionIncrement(t *testing.T) {
	v := createTestVault(t)

	if err := v.SetSecret("default", "DB_URL", "v1"); err != nil {
		t.Fatalf("SetSecret v1: %v", err)
	}

	// Get the initial version via the store directly to check.
	p, _ := v.store.GetProjectByName("default")
	entry1, _ := v.store.GetSecret(p.ID, "DB_URL")
	if entry1.Version != 1 {
		t.Fatalf("expected version 1, got %d", entry1.Version)
	}

	// Set the same key again.
	if err := v.SetSecret("default", "DB_URL", "v2"); err != nil {
		t.Fatalf("SetSecret v2: %v", err)
	}

	entry2, _ := v.store.GetSecret(p.ID, "DB_URL")
	if entry2.Version != 2 {
		t.Fatalf("expected version 2, got %d", entry2.Version)
	}

	// Value should be updated.
	got, err := v.GetSecret("default", "DB_URL")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "v2" {
		t.Fatalf("expected 'v2', got %q", got)
	}
}

func TestListSecrets(t *testing.T) {
	v := createTestVault(t)

	v.SetSecret("default", "KEY_A", "a")
	v.SetSecret("default", "KEY_B", "b")
	v.SetSecret("default", "KEY_C", "c")

	keys, err := v.ListSecrets("default")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}

	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	for _, expected := range []string{"KEY_A", "KEY_B", "KEY_C"} {
		if !keySet[expected] {
			t.Fatalf("expected key %q in list", expected)
		}
	}
}

func TestGetAllSecrets(t *testing.T) {
	v := createTestVault(t)

	v.SetSecret("default", "SECRET_1", "value1")
	v.SetSecret("default", "SECRET_2", "value2")

	all, err := v.GetAllSecrets("default")
	if err != nil {
		t.Fatalf("GetAllSecrets: %v", err)
	}

	if len(all) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(all))
	}
	if all["SECRET_1"] != "value1" {
		t.Fatalf("expected SECRET_1='value1', got %q", all["SECRET_1"])
	}
	if all["SECRET_2"] != "value2" {
		t.Fatalf("expected SECRET_2='value2', got %q", all["SECRET_2"])
	}
}

func TestDeleteSecret(t *testing.T) {
	v := createTestVault(t)

	v.SetSecret("default", "TO_DELETE", "val")

	if err := v.DeleteSecret("default", "TO_DELETE"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	_, err := v.GetSecret("default", "TO_DELETE")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestDeleteProject(t *testing.T) {
	v := createTestVault(t)

	v.CreateProject("to-delete", "")

	if err := v.DeleteProject("to-delete"); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}

	_, err := v.GetProject("to-delete")
	if !errors.Is(err, ErrProjectNotFound) {
		t.Fatalf("expected ErrProjectNotFound, got %v", err)
	}
}

func TestSetCurrentProject(t *testing.T) {
	v := createTestVault(t)

	v.CreateProject("staging", "Staging env")

	if err := v.SetCurrentProject("staging"); err != nil {
		t.Fatalf("SetCurrentProject: %v", err)
	}

	cur, err := v.GetCurrentProject()
	if err != nil {
		t.Fatalf("GetCurrentProject: %v", err)
	}
	if cur != "staging" {
		t.Fatalf("expected 'staging', got %q", cur)
	}

	// Setting a non-existent project should fail.
	err = v.SetCurrentProject("nonexistent")
	if !errors.Is(err, ErrProjectNotFound) {
		t.Fatalf("expected ErrProjectNotFound, got %v", err)
	}
}

func TestRotatePassphrase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Store a secret before rotation.
	v.SetSecret("default", "PERSIST", "should-survive-rotation")

	newPassphrase := "new-passphrase-456"
	if err := v.RotatePassphrase(testPassphrase, newPassphrase); err != nil {
		t.Fatalf("RotatePassphrase: %v", err)
	}
	v.Close()

	// Open and unlock with the new passphrase.
	v2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after rotation: %v", err)
	}
	defer v2.Close()

	// Old passphrase should fail.
	err = v2.Unlock(testPassphrase)
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase for old passphrase, got %v", err)
	}

	// New passphrase should work.
	if err := v2.Unlock(newPassphrase); err != nil {
		t.Fatalf("Unlock with new passphrase: %v", err)
	}

	// Secret should still be accessible.
	got, err := v2.GetSecret("default", "PERSIST")
	if err != nil {
		t.Fatalf("GetSecret after rotation: %v", err)
	}
	if got != "should-survive-rotation" {
		t.Fatalf("expected 'should-survive-rotation', got %q", got)
	}
}

func TestVaultLocked_OperationsFail(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	v.Close()

	v2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer v2.Close()

	// All mutating operations should fail with ErrLocked.
	_, err = v2.CreateProject("test", "")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("CreateProject: expected ErrLocked, got %v", err)
	}

	err = v2.SetSecret("default", "KEY", "val")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("SetSecret: expected ErrLocked, got %v", err)
	}

	_, err = v2.GetSecret("default", "KEY")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("GetSecret: expected ErrLocked, got %v", err)
	}

	_, err = v2.GetAllSecrets("default")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("GetAllSecrets: expected ErrLocked, got %v", err)
	}
}
