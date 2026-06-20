package identity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

func TestNewListLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	rec, path, err := New(dir, "ci")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if rec == "" || path == "" {
		t.Fatal("New returned empty recipient/path")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file perm = %#o, want 0600", perm)
	}

	// Duplicate must not overwrite.
	if _, _, derr := New(dir, "ci"); derr == nil {
		t.Error("creating a duplicate identity should fail")
	}

	// Invalid / path-traversal names (incl. empty) rejected.
	for _, bad := range []string{"", "../evil", "a/b", "has space"} {
		if _, _, berr := New(dir, bad); berr == nil {
			t.Errorf("New(%q) should be rejected", bad)
		}
	}

	// Load round-trips to the same recipient.
	id, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := crypto.EncodeRecipient(id.Recipient()); got != rec {
		t.Errorf("Load recipient = %s, want %s", got, rec)
	}

	// List returns the entry, public recipient only.
	entries, err := List(dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "ci" || entries[0].Recipient != rec {
		t.Errorf("List = %+v, want one 'ci' entry with recipient %s", entries, rec)
	}
}

func TestListMissingDir(t *testing.T) {
	entries, err := List(t.TempDir()) // no identities/ subdir yet
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List on missing dir = %v, want empty", entries)
	}
}

func TestFile(t *testing.T) {
	// Empty name defaults to "default" (for the decrypt path).
	p, err := File("/vault", "")
	if err != nil {
		t.Fatalf("File(empty): %v", err)
	}
	if want := filepath.Join("/vault", "identities", "default.key"); p != want {
		t.Errorf("File(empty) = %s, want %s", p, want)
	}
	// Traversal rejected.
	if _, err := File("/vault", "../evil"); err == nil {
		t.Error("File(../evil) should error")
	}
}
