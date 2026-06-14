package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

// captureStderr mirrors captureStdout for the os.Stderr stream.
func captureStderr(t *testing.T, fn func()) []byte {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	return buf[:n]
}

func TestResolveIdentityEnvKey(t *testing.T) {
	withVaultDir(t, t.TempDir())
	id := mustGenIdentity(t)
	t.Setenv(envIdentityKey, crypto.EncodeIdentity(id))

	got, source, err := resolveIdentity("default") // no file present
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	if got == nil || source != "env-key" {
		t.Fatalf("want env-key identity, got source=%q id=%v", source, got)
	}
	if !equalRecipients(got, id) {
		t.Error("env-key resolved a different identity")
	}
}

func TestResolveIdentityFileBeatsEnvKey(t *testing.T) {
	withVaultDir(t, t.TempDir())
	fileID := mustGenIdentity(t)
	writeTestIdentity(t, "default", fileID)
	t.Setenv(envIdentityKey, crypto.EncodeIdentity(mustGenIdentity(t))) // a different env key

	got, source, err := resolveIdentity("default")
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	if source != "file" {
		t.Fatalf("file must win over env key, got source=%q", source)
	}
	if !equalRecipients(got, fileID) {
		t.Error("resolved the env key instead of the file")
	}
}

func TestResolveIdentityLocked(t *testing.T) {
	withVaultDir(t, t.TempDir())
	// Ensure no env key leaks in from the host.
	t.Setenv(envIdentityKey, "")
	got, source, err := resolveIdentity("default")
	if err != nil || got != nil || source != "" {
		t.Fatalf("locked state should be (nil, \"\", nil), got id=%v source=%q err=%v", got, source, err)
	}
}

func TestResolveIdentityEnvKeyMalformedNoLeak(t *testing.T) {
	withVaultDir(t, t.TempDir())
	const secretish = "tvault-key1SUPERSECRETGARBAGEZZZZ"
	t.Setenv(envIdentityKey, secretish)

	_, _, err := resolveIdentity("default")
	if err == nil {
		t.Fatal("malformed env key should error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETGARBAGE") {
		t.Errorf("error leaked the key value: %v", err)
	}
}

func TestResolveIdentityBadName(t *testing.T) {
	withVaultDir(t, t.TempDir())
	if _, _, err := resolveIdentity("../../etc/x"); err == nil {
		t.Fatal("traversal name should be rejected")
	}
}

func TestLoadIdentityWarnsOnLoosePerms(t *testing.T) {
	dir := t.TempDir()
	withVaultDir(t, dir)
	id := mustGenIdentity(t)
	if err := os.MkdirAll(identitiesDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(identitiesDir(), "loose.key")
	if err := os.WriteFile(path, []byte(crypto.EncodeIdentity(id)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var loaded *crypto.Identity
	stderr := captureStderr(t, func() {
		var lerr error
		loaded, lerr = loadIdentity(path)
		if lerr != nil {
			t.Fatalf("loadIdentity: %v", lerr)
		}
	})
	if loaded == nil {
		t.Fatal("identity should still load")
	}
	if !strings.Contains(string(stderr), "group/world-readable") {
		t.Errorf("expected a loose-perms warning, got %q", stderr)
	}
}

func TestIdentityExportForceStdoutOnly(t *testing.T) {
	withVaultDir(t, t.TempDir())
	id := mustGenIdentity(t)
	writeTestIdentity(t, "ci", id)

	old := identityExportForce
	identityExportForce = true
	defer func() { identityExportForce = old }()

	var stdout []byte
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := runIdentityExport(nil, []string{"ci"}); err != nil {
				t.Fatalf("export: %v", err)
			}
		})
	})

	priv := strings.TrimSpace(string(stdout))
	if priv != crypto.EncodeIdentity(id) {
		t.Errorf("stdout should be exactly the private key, got %q", priv)
	}
	if !strings.Contains(string(stderr), "WARNING") {
		t.Errorf("expected a WARNING on stderr, got %q", stderr)
	}
	if strings.Contains(string(stderr), priv) {
		t.Error("private key leaked onto stderr")
	}
	// The exported key must decode back to the same identity.
	back, err := crypto.DecodeIdentity(priv)
	if err != nil || !equalRecipients(back, id) {
		t.Errorf("exported key does not round-trip: %v", err)
	}
}

func TestIdentityExportTTYRefusal(t *testing.T) {
	withVaultDir(t, t.TempDir())
	writeTestIdentity(t, "ci", mustGenIdentity(t))

	old := identityExportForce
	identityExportForce = false // no --force
	defer func() { identityExportForce = old }()

	var err error
	// captureStdout points os.Stdout at a pipe, which is never a terminal,
	// so the non-TTY refusal path must trigger.
	out := captureStdout(t, func() {
		err = runIdentityExport(nil, []string{"ci"})
	})
	if err == nil {
		t.Fatal("export to a non-terminal without --force must error")
	}
	if len(strings.TrimSpace(string(out))) != 0 {
		t.Errorf("no key should be printed on refusal, got %q", out)
	}
}

func TestIdentityExportJSON(t *testing.T) {
	withVaultDir(t, t.TempDir())
	id := mustGenIdentity(t)
	writeTestIdentity(t, "ci", id)

	oldF, oldJ := identityExportForce, jsonOutput
	identityExportForce, jsonOutput = true, true
	defer func() { identityExportForce, jsonOutput = oldF, oldJ }()

	out := captureStdout(t, func() {
		if err := runIdentityExport(nil, []string{"ci"}); err != nil {
			t.Fatalf("export --json: %v", err)
		}
	})
	var m map[string]string
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if m["name"] != "ci" {
		t.Errorf("name = %q, want ci", m["name"])
	}
	if m["recipient"] != crypto.EncodeRecipient(id.Recipient()) {
		t.Errorf("recipient mismatch: %q", m["recipient"])
	}
	back, err := crypto.DecodeIdentity(m["private"])
	if err != nil || !equalRecipients(back, id) {
		t.Errorf("private key does not round-trip: %v", err)
	}
}

func TestWarnEnvKeyFilePrecedence(t *testing.T) {
	// With the env key set, a "file" source must warn that the file wins.
	t.Setenv(envIdentityKey, "tvault-key1placeholder")
	var withKey strings.Builder
	warnEnvKeyUsed(&withKey, "file", "open")
	if !strings.Contains(withKey.String(), "takes precedence") {
		t.Errorf("expected a file-precedence warning, got %q", withKey.String())
	}

	// With no env key, a "file" source must be silent.
	t.Setenv(envIdentityKey, "")
	var noKey strings.Builder
	warnEnvKeyUsed(&noKey, "file", "open")
	if noKey.Len() != 0 {
		t.Errorf("expected no warning when env key is unset, got %q", noKey.String())
	}
}

func equalRecipients(a, b *crypto.Identity) bool {
	return string(a.Recipient()) == string(b.Recipient())
}
