package vault

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
)

func TestUnlockWithKEK_RoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Grab the KEK from the freshly-created (unlocked) vault.
	kek, err := v.KEK()
	if err != nil {
		t.Fatalf("KEK: %v", err)
	}
	v.Close()

	// Re-open: should be locked.
	v2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer v2.Close()
	if v2.IsUnlocked() {
		t.Fatal("vault should be locked after Open")
	}

	// Unlock with the cached KEK — mirrors how the agent reopens the vault.
	if err := v2.UnlockWithKEK(kek); err != nil {
		t.Fatalf("UnlockWithKEK: %v", err)
	}
	if !v2.IsUnlocked() {
		t.Fatal("vault should be unlocked after UnlockWithKEK")
	}

	// The vault keeps its own copy; the caller-supplied kek is still usable.
	if _, err := v2.GetCurrentProject(); err != nil {
		t.Fatalf("GetCurrentProject after UnlockWithKEK: %v", err)
	}
}

func TestUnlockWithKEK_WrongKEK(t *testing.T) {
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

	// A garbage KEK of the correct length must be rejected by the verifier.
	garbage := make([]byte, 32)
	if err := v2.UnlockWithKEK(garbage); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase for garbage KEK, got %v", err)
	}
	if v2.IsUnlocked() {
		t.Fatal("vault should remain locked after wrong KEK")
	}
}

func TestStatus_Unlocked(t *testing.T) {
	v := createTestVault(t)

	st := v.Status()
	if !st.IsUnlocked {
		t.Fatal("expected Status.IsUnlocked == true on fresh vault")
	}
	if st.ProjectCount != 1 {
		t.Fatalf("expected ProjectCount 1 (default project), got %d", st.ProjectCount)
	}
	if st.VaultID == "" {
		t.Fatal("expected non-empty VaultID")
	}
	if st.Path == "" {
		t.Fatal("expected non-empty Path")
	}
	if st.CreatedAt == "" {
		t.Fatal("expected non-empty CreatedAt")
	}

	// Adding a project bumps the count.
	if _, err := v.CreateProject("extra", ""); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if st := v.Status(); st.ProjectCount != 2 {
		t.Fatalf("expected ProjectCount 2 after CreateProject, got %d", st.ProjectCount)
	}
}

func TestStatus_Locked(t *testing.T) {
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

	st := v2.Status()
	if st.IsUnlocked {
		t.Fatal("expected Status.IsUnlocked == false on reopened (locked) vault")
	}
	// Metadata is readable without unlocking.
	if st.VaultID == "" {
		t.Fatal("expected non-empty VaultID even when locked")
	}
	if st.ProjectCount != 1 {
		t.Fatalf("expected ProjectCount 1 even when locked, got %d", st.ProjectCount)
	}
}

func TestAppendAudit_RoundTrip(t *testing.T) {
	v := createTestVault(t)

	entry := &store.AuditEntry{
		Action:       "get_secret",
		ResourceType: "secret",
		ResourceName: "API_KEY",
		Timestamp:    time.Now().UTC(),
		Metadata:     map[string]any{"project": "default"},
	}
	if err := v.AppendAudit(entry); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	entries, err := v.ListAudit(store.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry after AppendAudit")
	}

	var found *store.AuditEntry
	for _, e := range entries {
		if e.Action == "get_secret" && e.ResourceName == "API_KEY" {
			found = e
			break
		}
	}
	if found == nil {
		t.Fatal("appended audit entry not found in ListAudit")
	}
	if found.ResourceType != "secret" {
		t.Fatalf("expected ResourceType 'secret', got %q", found.ResourceType)
	}
	if got := found.Metadata["project"]; got != "default" {
		t.Fatalf("expected metadata project 'default', got %v", got)
	}
	if found.Timestamp.IsZero() {
		t.Fatal("expected a populated Timestamp on the audit entry")
	}
}

func TestListAudit_ActionFilter(t *testing.T) {
	v := createTestVault(t)

	now := time.Now().UTC()
	if err := v.AppendAudit(&store.AuditEntry{Action: "create_project", ResourceType: "project", Timestamp: now}); err != nil {
		t.Fatalf("AppendAudit create_project: %v", err)
	}
	if err := v.AppendAudit(&store.AuditEntry{Action: "delete_project", ResourceType: "project", Timestamp: now.Add(time.Second)}); err != nil {
		t.Fatalf("AppendAudit delete_project: %v", err)
	}

	entries, err := v.ListAudit(store.AuditFilter{Action: "delete_project"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	for _, e := range entries {
		if e.Action != "delete_project" {
			t.Fatalf("filter leaked action %q", e.Action)
		}
	}
}
