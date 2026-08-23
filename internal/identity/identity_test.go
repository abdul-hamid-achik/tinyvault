package identity

import (
	"os"
	"path/filepath"
	"strings"
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

func TestResolveEnvKey(t *testing.T) {
	dir := t.TempDir()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvKey, crypto.EncodeIdentity(id))

	got, source, rerr := Resolve(dir, "default")
	if rerr != nil {
		t.Fatalf("Resolve: %v", rerr)
	}
	if got == nil || source != "env-key" {
		t.Fatalf("want env-key identity, got source=%q id=%v", source, got)
	}
	if crypto.EncodeRecipient(got.Recipient()) != crypto.EncodeRecipient(id.Recipient()) {
		t.Error("env-key resolved a different identity")
	}
}

func TestResolveFileBeatsEnvKey(t *testing.T) {
	dir := t.TempDir()
	fileRec, _, err := New(dir, "default")
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvKey, crypto.EncodeIdentity(other))

	got, source, rerr := Resolve(dir, "default")
	if rerr != nil {
		t.Fatalf("Resolve: %v", rerr)
	}
	if source != "file" {
		t.Fatalf("file must win over env key, got source=%q", source)
	}
	if crypto.EncodeRecipient(got.Recipient()) != fileRec {
		t.Error("resolved the env key instead of the file")
	}
}

func TestResolveLocked(t *testing.T) {
	t.Setenv(EnvKey, "")
	got, source, err := Resolve(t.TempDir(), "default")
	if err != nil || got != nil || source != "" {
		t.Fatalf("locked state should be (nil, \"\", nil), got id=%v source=%q err=%v", got, source, err)
	}
}

func TestResolveEnvKeyMalformedNoLeak(t *testing.T) {
	const secretish = "tvault-key1SUPERSECRETGARBAGEZZZZ"
	t.Setenv(EnvKey, secretish)
	_, _, err := Resolve(t.TempDir(), "default")
	if err == nil {
		t.Fatal("malformed env key should error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETGARBAGE") {
		t.Errorf("error leaked the key value: %v", err)
	}
}

func TestResolveBadName(t *testing.T) {
	if _, _, err := Resolve(t.TempDir(), "../../etc/x"); err == nil {
		t.Fatal("traversal name should be rejected")
	}
}
