package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateDirPrefersXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/custom/state")
	if got, want := StateDir(), filepath.Join("/custom/state", "tvault"); got != want {
		t.Fatalf("StateDir() = %q, want %q", got, want)
	}
}

func TestStateDirFallsBackToLocalState(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	if got, want := StateDir(), filepath.Join(home, ".local", "state", "tvault"); got != want {
		t.Fatalf("StateDir() = %q, want %q", got, want)
	}
}

func TestParseLevel(t *testing.T) {
	for _, in := range []string{"", "debug", "INFO", " warn ", "warning", "error"} {
		if _, err := ParseLevel(in); err != nil {
			t.Errorf("ParseLevel(%q) errored: %v", in, err)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("ParseLevel(\"verbose\") should reject an unknown level so a config typo surfaces")
	}
}

// TestNewWritesOwnerOnlyFile guards the permission posture: log records name
// projects and keys, so neither the directory nor the file may be group- or
// world-readable.
func TestNewWritesOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "nested")

	logger, closer, err := New("agent", Options{Dir: logDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info("hello", "project", "demo")
	if err := closer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	di, err := os.Stat(logDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != dirPerm {
		t.Errorf("log dir perm = %#o, want %#o", perm, dirPerm)
	}

	path := Path("agent", Options{Dir: logDir})
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != filePerm {
		t.Errorf("log file perm = %#o, want %#o", perm, filePerm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Errorf("log file missing the record, got %q", data)
	}
}

// TestNewTightensPreexistingLooseFile covers a log file left behind by an older
// build or a permissive umask.
func TestNewTightensPreexistingLooseFile(t *testing.T) {
	dir := t.TempDir()
	path := Path("agent", Options{Dir: dir})
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, closer, err := New("agent", Options{Dir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = closer.Close() }()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != filePerm {
		t.Errorf("log file perm = %#o, want %#o (a loose pre-existing file must be tightened)", perm, filePerm)
	}
}

func TestNewRotatesOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := Path("agent", Options{Dir: dir})
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 128)), filePerm); err != nil {
		t.Fatal(err)
	}

	_, closer, err := New("agent", Options{Dir: dir, MaxBytes: 64})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = closer.Close() }()

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("oversized log was not rotated to .1: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() >= 128 {
		t.Errorf("current log still holds the rotated content (size %d)", fi.Size())
	}
}

func TestResetRemovesBothGenerations(t *testing.T) {
	dir := t.TempDir()
	opts := Options{Dir: dir}
	path := Path("agent", opts)
	for _, p := range []string{path, path + ".1"} {
		if err := os.WriteFile(p, []byte("x"), filePerm); err != nil {
			t.Fatal(err)
		}
	}

	if err := Reset("agent", opts); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	for _, p := range []string{path, path + ".1"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists after Reset", p)
		}
	}
	// Reset on an already-clean state must succeed, so a deploy script can call
	// it unconditionally.
	if err := Reset("agent", opts); err != nil {
		t.Errorf("Reset on missing files should succeed, got %v", err)
	}
}
