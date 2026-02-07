package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestStore(t *testing.T) *BoltStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ---------------------------------------------------------------------------
// Store creation
// ---------------------------------------------------------------------------

func TestNewBoltStore_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")

	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("database file is empty")
	}
}

func TestBoltStore_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")

	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}

// ---------------------------------------------------------------------------
// Meta CRUD
// ---------------------------------------------------------------------------

func TestBoltStore_MetaCRUD(t *testing.T) {
	s := newTestStore(t)

	// Initially no meta.
	_, err := s.GetMeta()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	meta := &VaultMeta{
		Version:   1,
		Salt:      []byte("test-salt-16byte"),
		Verifier:  []byte("encrypted-verifier"),
		CreatedAt: now,
		VaultID:   uuid.New().String(),
	}

	if err := s.SetMeta(meta); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	got, err := s.GetMeta()
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}

	if got.Version != meta.Version {
		t.Errorf("Version = %d, want %d", got.Version, meta.Version)
	}
	if string(got.Salt) != string(meta.Salt) {
		t.Errorf("Salt mismatch")
	}
	if string(got.Verifier) != string(meta.Verifier) {
		t.Errorf("Verifier mismatch")
	}
	if got.VaultID != meta.VaultID {
		t.Errorf("VaultID = %q, want %q", got.VaultID, meta.VaultID)
	}
	if !got.CreatedAt.Equal(meta.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, meta.CreatedAt)
	}

	// Update meta.
	meta.Version = 2
	if err := s.SetMeta(meta); err != nil {
		t.Fatalf("SetMeta (update): %v", err)
	}
	got, err = s.GetMeta()
	if err != nil {
		t.Fatalf("GetMeta after update: %v", err)
	}
	if got.Version != 2 {
		t.Errorf("Version after update = %d, want 2", got.Version)
	}
}

// ---------------------------------------------------------------------------
// Config CRUD
// ---------------------------------------------------------------------------

func TestBoltStore_ConfigCRUD(t *testing.T) {
	s := newTestStore(t)

	// Key not set yet.
	_, err := s.GetConfig("current_project")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	if err := s.SetConfig("current_project", "abc-123"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	val, err := s.GetConfig("current_project")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if val != "abc-123" {
		t.Errorf("GetConfig = %q, want %q", val, "abc-123")
	}

	// Overwrite.
	if err := s.SetConfig("current_project", "xyz-456"); err != nil {
		t.Fatalf("SetConfig (overwrite): %v", err)
	}
	val, err = s.GetConfig("current_project")
	if err != nil {
		t.Fatalf("GetConfig after overwrite: %v", err)
	}
	if val != "xyz-456" {
		t.Errorf("GetConfig after overwrite = %q, want %q", val, "xyz-456")
	}
}

// ---------------------------------------------------------------------------
// Project CRUD
// ---------------------------------------------------------------------------

func TestBoltStore_ProjectCRUD(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)

	p := &Project{
		ID:           uuid.New(),
		Name:         "my-app",
		Description:  "Production secrets",
		EncryptedDEK: []byte("encrypted-dek-data"),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Create.
	if err := s.CreateProject(p); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	// Get by ID.
	got, err := s.GetProject(p.ID)
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if got.Name != "my-app" {
		t.Errorf("Name = %q, want %q", got.Name, "my-app")
	}
	if got.Description != "Production secrets" {
		t.Errorf("Description = %q, want %q", got.Description, "Production secrets")
	}
	if string(got.EncryptedDEK) != string(p.EncryptedDEK) {
		t.Errorf("EncryptedDEK mismatch")
	}

	// Get by name.
	got, err = s.GetProjectByName("my-app")
	if err != nil {
		t.Fatalf("GetProjectByName: %v", err)
	}
	if got.ID != p.ID {
		t.Errorf("ID = %v, want %v", got.ID, p.ID)
	}

	// List (should contain our project).
	projects, err := s.ListProjects()
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("ListProjects returned %d projects, want 1", len(projects))
	}
	if projects[0].Name != "my-app" {
		t.Errorf("ListProjects[0].Name = %q, want %q", projects[0].Name, "my-app")
	}

	// Update.
	p.Description = "Staging secrets"
	p.UpdatedAt = time.Now().UTC().Truncate(time.Millisecond)
	if err := s.UpdateProject(p); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	got, err = s.GetProject(p.ID)
	if err != nil {
		t.Fatalf("GetProject after update: %v", err)
	}
	if got.Description != "Staging secrets" {
		t.Errorf("Description after update = %q, want %q", got.Description, "Staging secrets")
	}

	// Soft delete.
	if err := s.DeleteProject(p.ID); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}

	// The record still exists but is soft-deleted.
	got, err = s.GetProject(p.ID)
	if err != nil {
		t.Fatalf("GetProject after delete: %v", err)
	}
	if got.DeletedAt == nil {
		t.Error("DeletedAt should be set after soft delete")
	}

	// List should now be empty (soft-deleted projects are excluded).
	projects, err = s.ListProjects()
	if err != nil {
		t.Fatalf("ListProjects after delete: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("ListProjects after delete returned %d projects, want 0", len(projects))
	}

	// Name should be freed for reuse.
	_, err = s.GetProjectByName("my-app")
	if !errors.Is(err, ErrProjectNotFound) {
		t.Errorf("GetProjectByName after delete: expected ErrProjectNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Secret CRUD
// ---------------------------------------------------------------------------

func TestBoltStore_SecretCRUD(t *testing.T) {
	s := newTestStore(t)
	projID := uuid.New()
	now := time.Now().UTC().Truncate(time.Millisecond)

	entry := &SecretEntry{
		EncryptedValue: []byte("enc-value-1"),
		Version:        1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// Set.
	if err := s.SetSecret(projID, "DATABASE_URL", entry); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	// Get.
	got, err := s.GetSecret(projID, "DATABASE_URL")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got.EncryptedValue) != "enc-value-1" {
		t.Errorf("EncryptedValue = %q, want %q", got.EncryptedValue, "enc-value-1")
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}

	// Upsert: version should auto-increment.
	entry2 := &SecretEntry{
		EncryptedValue: []byte("enc-value-2"),
		Version:        1, // Will be overridden by upsert.
		CreatedAt:      now,
		UpdatedAt:      time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := s.SetSecret(projID, "DATABASE_URL", entry2); err != nil {
		t.Fatalf("SetSecret (upsert): %v", err)
	}
	got, err = s.GetSecret(projID, "DATABASE_URL")
	if err != nil {
		t.Fatalf("GetSecret after upsert: %v", err)
	}
	if got.Version != 2 {
		t.Errorf("Version after upsert = %d, want 2", got.Version)
	}
	if string(got.EncryptedValue) != "enc-value-2" {
		t.Errorf("EncryptedValue after upsert = %q, want %q", got.EncryptedValue, "enc-value-2")
	}
	// CreatedAt should be preserved from the original.
	if !got.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt should be preserved after upsert, got %v, want %v", got.CreatedAt, now)
	}

	// Add another secret.
	entry3 := &SecretEntry{
		EncryptedValue: []byte("enc-api-key"),
		Version:        1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.SetSecret(projID, "API_KEY", entry3); err != nil {
		t.Fatalf("SetSecret (API_KEY): %v", err)
	}

	// List keys.
	keys, err := s.ListSecretKeys(projID)
	if err != nil {
		t.Fatalf("ListSecretKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("ListSecretKeys returned %d keys, want 2", len(keys))
	}

	// List all secrets.
	secrets, err := s.ListSecrets(projID)
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("ListSecrets returned %d entries, want 2", len(secrets))
	}
	if _, ok := secrets["DATABASE_URL"]; !ok {
		t.Error("ListSecrets missing DATABASE_URL")
	}
	if _, ok := secrets["API_KEY"]; !ok {
		t.Error("ListSecrets missing API_KEY")
	}

	// Delete.
	if err := s.DeleteSecret(projID, "API_KEY"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	keys, err = s.ListSecretKeys(projID)
	if err != nil {
		t.Fatalf("ListSecretKeys after delete: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("ListSecretKeys after delete returned %d keys, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

func TestBoltStore_AuditLog(t *testing.T) {
	s := newTestStore(t)

	base := time.Now().UTC()

	for i := 0; i < 5; i++ {
		entry := &AuditEntry{
			Action:       "secret.set",
			ResourceType: "secret",
			ResourceID:   uuid.New().String(),
			ResourceName: "DB_PASSWORD",
			Timestamp:    base.Add(time.Duration(i) * time.Second),
			Metadata:     map[string]any{"version": float64(i + 1)},
		}
		if err := s.AppendAudit(entry); err != nil {
			t.Fatalf("AppendAudit %d: %v", i, err)
		}
	}

	// List all.
	entries, err := s.ListAudit(0)
	if err != nil {
		t.Fatalf("ListAudit(0): %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("ListAudit(0) returned %d entries, want 5", len(entries))
	}

	// Newest first.
	if entries[0].Timestamp.Before(entries[len(entries)-1].Timestamp) {
		t.Error("ListAudit should return newest first")
	}

	// List with limit.
	entries, err = s.ListAudit(3)
	if err != nil {
		t.Fatalf("ListAudit(3): %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("ListAudit(3) returned %d entries, want 3", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Not-found edge cases
// ---------------------------------------------------------------------------

func TestBoltStore_ProjectNotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.GetProject(uuid.New())
	if !errors.Is(err, ErrProjectNotFound) {
		t.Errorf("GetProject: expected ErrProjectNotFound, got %v", err)
	}

	_, err = s.GetProjectByName("nonexistent")
	if !errors.Is(err, ErrProjectNotFound) {
		t.Errorf("GetProjectByName: expected ErrProjectNotFound, got %v", err)
	}

	err = s.UpdateProject(&Project{ID: uuid.New(), Name: "ghost"})
	if !errors.Is(err, ErrProjectNotFound) {
		t.Errorf("UpdateProject: expected ErrProjectNotFound, got %v", err)
	}

	err = s.DeleteProject(uuid.New())
	if !errors.Is(err, ErrProjectNotFound) {
		t.Errorf("DeleteProject: expected ErrProjectNotFound, got %v", err)
	}
}

func TestBoltStore_SecretNotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.GetSecret(uuid.New(), "NONEXISTENT")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("GetSecret: expected ErrSecretNotFound, got %v", err)
	}

	err = s.DeleteSecret(uuid.New(), "NONEXISTENT")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("DeleteSecret: expected ErrSecretNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Duplicate project name
// ---------------------------------------------------------------------------

func TestBoltStore_DuplicateProjectName(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()

	p1 := &Project{
		ID:        uuid.New(),
		Name:      "my-app",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateProject(p1); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	p2 := &Project{
		ID:        uuid.New(),
		Name:      "my-app",
		CreatedAt: now,
		UpdatedAt: now,
	}
	err := s.CreateProject(p2)
	if !errors.Is(err, ErrDuplicateProjectName) {
		t.Errorf("expected ErrDuplicateProjectName, got %v", err)
	}

	// Renaming to an existing name should also fail.
	p3 := &Project{
		ID:        uuid.New(),
		Name:      "other-app",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateProject(p3); err != nil {
		t.Fatalf("CreateProject (other-app): %v", err)
	}

	p3.Name = "my-app"
	err = s.UpdateProject(p3)
	if !errors.Is(err, ErrDuplicateProjectName) {
		t.Errorf("UpdateProject rename: expected ErrDuplicateProjectName, got %v", err)
	}
}
