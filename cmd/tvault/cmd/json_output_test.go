package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the --json surface of backup / restore / key rotate, and for the
// shared encoder contract every --json command now goes through: valid JSON on
// stdout, nothing but JSON on stdout, and no HTML escaping of & < >.

// withJSONOutput flips the global --json flag for one test.
func withJSONOutput(t *testing.T) {
	t.Helper()
	old := jsonOutput
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = old })
}

// mustParseJSON fails the test unless raw is a single valid JSON object.
func mustParseJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, raw)
	}
	return doc
}

// assertRFC3339 checks a timestamp field round-trips as RFC3339.
func assertRFC3339(t *testing.T, doc map[string]any, field string) {
	t.Helper()
	s, ok := doc[field].(string)
	if !ok || s == "" {
		t.Fatalf("%s = %v, want a non-empty string", field, doc[field])
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		t.Errorf("%s = %q is not RFC3339: %v", field, s, err)
	}
}

// The backup JSON must be pure stdout JSON describing the snapshot, and must
// not contain the value of any secret stored in the vault.
func TestBackupJSONReportsSnapshotMetadata(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "API_KEY", "sk-MUST-NOT-APPEAR-9f3a")

	withJSONOutput(t)
	dst := filepath.Join(t.TempDir(), "snap.db")
	stdout, _ := captureStdoutErr(t, func() {
		if err := runBackup(nil, []string{dst}); err != nil {
			t.Fatalf("runBackup --json: %v", err)
		}
	})

	doc := mustParseJSON(t, stdout)
	if doc["path"] != dst {
		t.Errorf("path = %v, want %s", doc["path"], dst)
	}
	if doc["compressed"] != false {
		t.Errorf("compressed = %v, want false for a plain .db destination", doc["compressed"])
	}
	if doc["immutable"] != false {
		t.Errorf("immutable = %v, want false (not requested)", doc["immutable"])
	}
	for _, field := range []string{"bytes", "raw_bytes"} {
		n, ok := doc[field].(float64)
		if !ok || n <= 0 {
			t.Errorf("%s = %v, want a positive number", field, doc[field])
		}
	}
	assertRFC3339(t, doc, "created_at")

	if strings.Contains(string(stdout), "sk-MUST-NOT-APPEAR") {
		t.Errorf("backup --json leaked a secret value:\n%s", stdout)
	}
	if strings.Contains(string(stdout), "✓") {
		t.Errorf("human success line mixed into --json stdout:\n%s", stdout)
	}
}

// A rotated snapshot is gzip-compressed, and the JSON must say so.
func TestBackupRotatedJSONReportsCompression(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "API_KEY", "sk-MUST-NOT-APPEAR-9f3a")

	dir := t.TempDir()
	backupDirFlag = dir
	clearImmutableOnCleanup(t, dir)

	withJSONOutput(t)
	stdout, _ := captureStdoutErr(t, func() {
		if err := runBackup(nil, nil); err != nil {
			t.Fatalf("runBackup --json (rotated): %v", err)
		}
	})

	doc := mustParseJSON(t, stdout)
	path, _ := doc["path"].(string)
	if !strings.HasSuffix(path, ".db.gz") {
		t.Fatalf("path = %q, want a rotated .db.gz snapshot", path)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("path = %q, want it inside --dir %s", path, dir)
	}
	if doc["compressed"] != true {
		t.Errorf("compressed = %v, want true", doc["compressed"])
	}
	raw, _ := doc["raw_bytes"].(float64)
	onDisk, _ := doc["bytes"].(float64)
	if raw <= 0 || onDisk <= 0 {
		t.Errorf("bytes = %v, raw_bytes = %v; want both positive", doc["bytes"], doc["raw_bytes"])
	}
	assertRFC3339(t, doc, "created_at")
	if strings.Contains(string(stdout), "sk-MUST-NOT-APPEAR") {
		t.Errorf("backup --json leaked a secret value:\n%s", stdout)
	}
}

// restore --json must report the source, the vault directory, and the
// pre-restore safety snapshot — and nothing else.
func TestRestoreJSONReportsSavedSnapshot(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "WHICH", "old-MUST-NOT-APPEAR")

	snap := filepath.Join(t.TempDir(), "snap.db")
	captureStdout(t, func() {
		if err := runBackup(nil, []string{snap}); err != nil {
			t.Fatalf("backup: %v", err)
		}
	})
	setVersionsForCLI(t, vaultPath, "WHICH", "new-MUST-NOT-APPEAR")

	restoreYes = true
	withJSONOutput(t)
	stdout, _ := captureStdoutErr(t, func() {
		if err := runRestore(nil, []string{snap}); err != nil {
			t.Fatalf("runRestore --json: %v", err)
		}
	})

	doc := mustParseJSON(t, stdout)
	if doc["restored"] != true {
		t.Errorf("restored = %v, want true", doc["restored"])
	}
	if doc["source"] != snap {
		t.Errorf("source = %v, want %s", doc["source"], snap)
	}
	if doc["vault_dir"] != vaultPath {
		t.Errorf("vault_dir = %v, want %s", doc["vault_dir"], vaultPath)
	}
	saved, _ := doc["saved_snapshot"].(string)
	if !strings.HasPrefix(filepath.Base(saved), "vault.db.pre-restore-") {
		t.Errorf("saved_snapshot = %q, want a vault.db.pre-restore-* copy", saved)
	}
	assertRFC3339(t, doc, "restored_at")

	if strings.Contains(string(stdout), "MUST-NOT-APPEAR") {
		t.Errorf("restore --json leaked a secret value:\n%s", stdout)
	}
	if strings.Contains(string(stdout), "ℹ") {
		t.Errorf("human info line mixed into --json stdout:\n%s", stdout)
	}
}

// A confirmation prompt cannot be answered on a machine-readable stream, so
// restore --json must refuse without --yes rather than silently cancel.
func TestRestoreJSONRequiresYes(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	snap := filepath.Join(t.TempDir(), "snap.db")
	captureStdout(t, func() {
		if err := runBackup(nil, []string{snap}); err != nil {
			t.Fatalf("backup: %v", err)
		}
	})

	restoreYes = false
	withJSONOutput(t)
	stdout, _ := captureStdoutErr(t, func() {
		err := runRestore(nil, []string{snap})
		if err == nil {
			t.Fatal("restore --json without --yes must fail, not silently cancel")
		}
		if !strings.Contains(err.Error(), "--yes") {
			t.Errorf("error = %v, want it to mention --yes", err)
		}
	})
	if len(bytes.TrimSpace(stdout)) != 0 {
		t.Errorf("stdout must be empty on failure, got %q", stdout)
	}
	// The vault must be untouched.
	if _, err := os.Stat(filepath.Join(vaultPath, "vault.db")); err != nil {
		t.Errorf("vault.db disappeared: %v", err)
	}
}

// key rotate cannot be driven without a TTY, so pin the document shape: the
// exact field names, and no passphrase material.
func TestKeyRotateJSONShape(t *testing.T) {
	var buf bytes.Buffer
	doc := keyRotateJSON{
		Rotated:   true,
		VaultDir:  "/tmp/vault",
		RotatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeJSONTo(&buf, doc); err != nil {
		t.Fatalf("writeJSONTo: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.Bytes())
	}
	want := map[string]bool{"rotated": true, "vault_dir": true, "rotated_at": true}
	for k := range got {
		if !want[k] {
			t.Errorf("unexpected field %q in key rotate JSON", k)
		}
		delete(want, k)
	}
	for k := range want {
		t.Errorf("key rotate JSON is missing field %q", k)
	}
	assertRFC3339(t, got, "rotated_at")
	if strings.Contains(strings.ToLower(buf.String()), "passphrase") {
		t.Errorf("key rotate JSON mentions a passphrase:\n%s", buf.String())
	}
}

// htmlEscapedForm builds the six-character escape Go's encoder emits for r
// when HTML escaping is ON — a backslash, 'u', and four hex digits. It is
// assembled from rune 92 so this file never has to spell the escape out.
func htmlEscapedForm(r rune) string {
	return string(rune(92)) + fmt.Sprintf("u%04x", r)
}

// assertNotHTMLEscaped fails the test if body carries the HTML-escaped form of
// & < or > — the three bytes SetEscapeHTML(true) (the encoding/json default)
// rewrites into a backslash-u sequence. A secrets tool must round-trip them
// literally: a DATABASE_URL with "?a=1&b=2" is corrupted otherwise. A quote is
// deliberately not checked, because JSON escapes those by specification.
func assertNotHTMLEscaped(t *testing.T, body string) {
	t.Helper()
	for _, r := range []rune{'&', '<', '>'} {
		if escaped := htmlEscapedForm(r); strings.Contains(body, escaped) {
			t.Errorf("output HTML-escapes %q as %s:\n%s", r, escaped, body)
		}
	}
}

// Regression: the shared encoder must not HTML-escape free text. A project
// description carrying an ampersand, angle brackets or a quote used to come
// out as a backslash-u escape sequence, which corrupts the value for any
// consumer of `projects list --json`.
func TestProjectsListJSONKeepsLiteralAmpersand(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	// Single quotes, not double: JSON escapes a double quote by
	// specification, so a literal-substring assertion needs a description
	// whose only JSON-sensitive bytes are the HTML-escaping ones.
	const desc = `a & b <c> 'd'`
	v := openTestVault(t, vaultPath)
	if _, err := v.CreateProject("webapp", desc); err != nil {
		t.Fatal(err)
	}
	v.Close()

	withJSONOutput(t)
	stdout, _ := captureStdoutErr(t, func() {
		if err := runProjectsList(nil, nil); err != nil {
			t.Fatalf("runProjectsList --json: %v", err)
		}
	})

	body := string(stdout)
	assertNotHTMLEscaped(t, body)
	if !strings.Contains(body, desc) {
		t.Errorf("literal description missing from --json output:\n%s", body)
	}

	var list []map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &list); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, body)
	}
	var found bool
	for _, p := range list {
		if p["name"] == "webapp" {
			found = true
			if p["description"] != desc {
				t.Errorf("description = %q, want %q", p["description"], desc)
			}
		}
	}
	if !found {
		t.Errorf("webapp missing from %v", list)
	}
}

// The docs manifest is machine-readable output too (runDocs with no topic
// always prints JSON): its descriptions carry placeholders such as
// vault-<time>.db.gz, which must survive literally.
func TestDocsCatalogJSONKeepsLiteralAngleBrackets(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Drain concurrently: the full catalog can exceed the pipe buffer.
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	if err := runDocs(nil, nil); err != nil {
		t.Fatalf("runDocs: %v", err)
	}
	_ = w.Close()
	body := string(<-done)

	assertNotHTMLEscaped(t, body)
	if !strings.Contains(body, "vault-<time>.db.gz") {
		t.Error("docs manifest lost a literal <time> placeholder")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("docs manifest is not valid JSON: %v", err)
	}
}

// sync --json must never carry the conflicting values. Until 2026-09-27 the
// untagged sync.Conflict fields put both plaintext sides of every conflict on
// stdout; see the comment on sync.Conflict for why the fields are gone rather
// than merely unexported from JSON.
func TestSyncJSONNeverCarriesConflictValues(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	const vaultSide = "postgres://vault-side-MUST-NOT-APPEAR"
	const envSide = "postgres://env-side-MUST-NOT-APPEAR"
	setVersionsForCLI(t, vaultPath, "DB_URL", vaultSide)

	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("DB_URL="+envSide+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldPath, oldDirection, oldOverwrite := syncPath, syncDirection, syncOverwrite
	syncPath, syncDirection, syncOverwrite = envFile, "mirror", false
	defer func() { syncPath, syncDirection, syncOverwrite = oldPath, oldDirection, oldOverwrite }()

	withJSONOutput(t)
	stdout, _ := captureStdoutErr(t, func() {
		if err := runSync(nil, nil); err != nil {
			t.Fatalf("runSync --json: %v", err)
		}
	})

	raw := string(stdout)
	if strings.Contains(raw, vaultSide) || strings.Contains(raw, envSide) {
		t.Fatalf("sync --json leaked a conflict value:\n%s", raw)
	}

	doc := mustParseJSON(t, stdout)
	conflicts, _ := doc["conflicts"].([]any)
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %v, want exactly one entry", doc["conflicts"])
	}
	c, _ := conflicts[0].(map[string]any)
	if c["key"] != "DB_URL" || c["resolution"] != "kept-vault" {
		t.Errorf("conflict = %v, want key DB_URL with resolution kept-vault", c)
	}
	if doc["direction"] != "mirror" {
		t.Errorf("direction = %v, want the string \"mirror\", not an iota", doc["direction"])
	}
}
