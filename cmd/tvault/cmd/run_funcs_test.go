package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunList covers both the prefix and non-prefix list paths plus the
// --json encoding.
func TestRunList(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	for _, k := range []string{"DB_HOST", "DB_PORT", "API_KEY"} {
		if err := v.SetSecret("default", k, "x"); err != nil {
			t.Fatal(err)
		}
	}
	v.Close()

	// Plain text list (all keys).
	out := captureStdout(t, func() {
		if err := runList(nil, nil); err != nil {
			t.Fatalf("runList: %v", err)
		}
	})
	for _, want := range []string{"API_KEY", "DB_HOST", "DB_PORT"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}

	// Prefix filter via the search path.
	oldPrefix := listPrefix
	listPrefix = "DB_"
	defer func() { listPrefix = oldPrefix }()

	out = captureStdout(t, func() {
		if err := runList(nil, nil); err != nil {
			t.Fatalf("runList --prefix: %v", err)
		}
	})
	if strings.Contains(string(out), "API_KEY") {
		t.Errorf("prefix list should exclude API_KEY:\n%s", out)
	}
	if !strings.Contains(string(out), "DB_HOST") {
		t.Errorf("prefix list missing DB_HOST:\n%s", out)
	}
}

func TestRunListJSON(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	out := captureStdout(t, func() {
		if err := runList(nil, nil); err != nil {
			t.Fatalf("runList --json: %v", err)
		}
	})
	var keys []string
	if err := json.Unmarshal(out, &keys); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if len(keys) != 1 || keys[0] != "FOO" {
		t.Errorf("got %v, want [FOO]", keys)
	}
}

// TestRunUse selects a project and verifies the stored current project.
func TestRunUse(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if _, err := v.CreateProject("staging", ""); err != nil {
		t.Fatal(err)
	}
	v.Close()

	if err := runUse(nil, []string{"staging"}); err != nil {
		t.Fatalf("runUse: %v", err)
	}

	v2 := openTestVault(t, vaultPath)
	defer v2.Close()
	cur, err := v2.GetCurrentProject()
	if err != nil {
		t.Fatal(err)
	}
	if cur != "staging" {
		t.Errorf("current project = %q, want staging", cur)
	}
}

func TestRunUseUnknownProject(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	err := runUse(nil, []string{"does-not-exist"})
	if err == nil {
		t.Fatal("expected error for unknown project")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got %v", err)
	}
}

func TestRunProjectsList(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if _, err := v.CreateProject("webapp", "the web app"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// Text output.
	out := captureStdout(t, func() {
		if err := runProjectsList(nil, nil); err != nil {
			t.Fatalf("runProjectsList: %v", err)
		}
	})
	for _, want := range []string{"NAME", "default", "webapp", "the web app"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("projects list missing %q:\n%s", want, out)
		}
	}

	// JSON output.
	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	out = captureStdout(t, func() {
		if err := runProjectsList(nil, nil); err != nil {
			t.Fatalf("runProjectsList --json: %v", err)
		}
	})
	var list []map[string]any
	if err := json.Unmarshal(out, &list); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if len(list) < 2 {
		t.Errorf("expected at least 2 projects, got %d", len(list))
	}
}

func TestRunProjectsUse(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if _, err := v.CreateProject("prod", ""); err != nil {
		t.Fatal(err)
	}
	v.Close()

	if err := runProjectsUse(nil, []string{"prod"}); err != nil {
		t.Fatalf("runProjectsUse: %v", err)
	}

	v2 := openTestVault(t, vaultPath)
	defer v2.Close()
	cur, err := v2.GetCurrentProject()
	if err != nil {
		t.Fatal(err)
	}
	if cur != "prod" {
		t.Errorf("current project = %q, want prod", cur)
	}

	// Unknown project errors.
	if err := runProjectsUse(nil, []string{"nope"}); err == nil {
		t.Error("expected error for unknown project")
	}
}

// TestRunExport exercises dotenv, json, yaml and k8s-secret formats.
func TestRunExport(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldFormat, oldName := exportFormat, exportK8sName
	defer func() { exportFormat, exportK8sName = oldFormat, oldName }()

	cases := []struct {
		format string
		want   string
	}{
		{"dotenv", "FOO=bar"},
		{"json", `"FOO": "bar"`},
		{"yaml", "FOO: bar"},
	}
	for _, tc := range cases {
		exportFormat = tc.format
		out := captureStdout(t, func() {
			if err := runExport(nil, nil); err != nil {
				t.Fatalf("runExport %s: %v", tc.format, err)
			}
		})
		if !strings.Contains(string(out), tc.want) {
			t.Errorf("export %s missing %q:\n%s", tc.format, tc.want, out)
		}
	}

	// k8s-secret requires --name.
	exportFormat = "k8s-secret"
	exportK8sName = ""
	if err := runExport(nil, nil); err == nil {
		t.Error("k8s-secret without --name should error")
	}
	exportK8sName = "app"
	out := captureStdout(t, func() {
		if err := runExport(nil, nil); err != nil {
			t.Fatalf("runExport k8s: %v", err)
		}
	})
	for _, want := range []string{"kind: Secret", "name: app", "FOO:"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("k8s export missing %q:\n%s", want, out)
		}
	}
}

func TestRunExportUnknownFormat(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldFormat := exportFormat
	exportFormat = "toml"
	defer func() { exportFormat = oldFormat }()

	if err := runExport(nil, nil); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestRunExportToFile(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	outPath := filepath.Join(t.TempDir(), "secrets.env")
	oldFormat, oldOut := exportFormat, exportOutput
	exportFormat, exportOutput = "dotenv", outPath
	defer func() { exportFormat, exportOutput = oldFormat, oldOut }()

	if err := runExport(nil, nil); err != nil {
		t.Fatalf("runExport -o: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "FOO=bar") {
		t.Errorf("written file missing FOO=bar:\n%s", data)
	}
}

// TestRunKeyRotateUninitialized covers the early "vault not found" branch
// of runKeyRotate without needing a TTY (the rest of the function prompts
// for passphrases interactively and is exercised via the vault package).
func TestRunKeyRotateUninitialized(t *testing.T) {
	withVaultDir(t, filepath.Join(t.TempDir(), "missing"))
	if err := runKeyRotate(nil, nil); err == nil {
		t.Error("expected error rotating an uninitialized vault")
	}
}

func TestRunLockAndUnlock(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	// Lock just opens + locks; should not error.
	if err := runLock(nil, nil); err != nil {
		t.Fatalf("runLock: %v", err)
	}

	// Unlock uses TVAULT_PASSPHRASE (set by the helper).
	if err := runUnlock(nil, nil); err != nil {
		t.Fatalf("runUnlock: %v", err)
	}
}

func TestRunLockUninitialized(t *testing.T) {
	withVaultDir(t, filepath.Join(t.TempDir(), "missing"))
	if err := runLock(nil, nil); err == nil {
		t.Error("expected error locking an uninitialized vault")
	}
	if err := runUnlock(nil, nil); err == nil {
		t.Error("expected error unlocking an uninitialized vault")
	}
}

func TestRunUnlockBadPassphrase(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	t.Setenv("TVAULT_PASSPHRASE", "wrong-passphrase")
	if err := runUnlock(nil, nil); err == nil {
		t.Error("expected error with wrong passphrase")
	}
}

// TestPrintDiff drives the human-readable diff renderer for both the
// in-sync and out-of-sync branches.
func TestPrintDiff(t *testing.T) {
	inSync := diffResult{
		Project: "default", File: ".env",
		OnlyInVault: []string{}, OnlyInFile: []string{},
		InBoth: []string{"FOO"}, InSync: true,
	}
	_ = captureStderr(t, func() { printDiff(inSync) })

	outOfSync := diffResult{
		Project: "default", File: ".env",
		OnlyInVault: []string{"A"}, OnlyInFile: []string{"B"},
		InBoth:     []string{"FOO"},
		ValueDiffs: map[string]string{"FOO": "differs"},
		InSync:     false,
	}
	_ = captureStderr(t, func() { printDiff(outOfSync) })
}

// TestRunDiffText exercises the non-JSON runDiff path (printDiff).
func TestRunDiffText(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "ONLY_VAULT", "x"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("ONLY_FILE=y\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldProj, oldVals := projectName, diffValues
	projectName, diffValues = "default", false
	defer func() { projectName, diffValues = oldProj, oldVals }()

	_ = captureStderr(t, func() {
		if err := runDiff(nil, []string{envPath}); err != nil {
			t.Fatalf("runDiff: %v", err)
		}
	})
}

// TestDocsFindAndPrintFeature covers findFeature (hit + miss) and
// printFeature on a known feature.
func TestDocsFindAndPrintFeature(t *testing.T) {
	cat := fullCatalog()

	f, ok := findFeature(cat, "encrypted-storage")
	if !ok {
		t.Fatal("findFeature should find encrypted-storage")
	}
	if _, miss := findFeature(cat, "no-such-feature"); miss {
		t.Error("findFeature should miss an unknown feature")
	}

	out := captureStdout(t, func() {
		if err := printFeature(f); err != nil {
			t.Fatalf("printFeature: %v", err)
		}
	})
	if !strings.Contains(string(out), "encrypted-storage") {
		t.Errorf("printFeature output missing feature name:\n%s", out)
	}
	if !strings.Contains(string(out), "Commands:") {
		t.Errorf("printFeature output missing commands:\n%s", out)
	}
}

// TestRunDocsNamedFeature drives runDocs with a feature name (the
// findFeature → printFeature fallback) and an unknown topic error.
func TestRunDocsNamedFeature(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runDocs(nil, []string{"secret-versioning"}); err != nil {
			t.Fatalf("runDocs feature: %v", err)
		}
	})
	if !strings.Contains(string(out), "secret-versioning") {
		t.Errorf("runDocs feature output missing name:\n%s", out)
	}

	if err := runDocs(nil, []string{"totally-unknown-topic"}); err == nil {
		t.Error("expected error for unknown topic/feature")
	}
}

func TestOverwriteHint(t *testing.T) {
	if got := overwriteHint(true); got == "" {
		t.Error("preview hint should be non-empty")
	}
	if got := overwriteHint(false); got != "" {
		t.Errorf("non-preview hint should be empty, got %q", got)
	}
}

// --- git-filter management commands ----------------------------------------

func TestRunGitFilterInstallStatusTrackUninstall(t *testing.T) {
	root, rec := gitFilterRepo(t)

	// Install with a seeded recipient.
	oldRecips := gitFilterRecipients
	gitFilterRecipients = []string{rec}
	defer func() { gitFilterRecipients = oldRecips }()

	_ = captureStderr(t, func() {
		if err := runGitFilterInstall(nil, nil); err != nil {
			t.Fatalf("install: %v", err)
		}
	})

	// .tvault-recipients should now contain the recipient.
	recs, err := repoRecipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Errorf("expected 1 recipient after install, got %d", len(recs))
	}

	// Track two patterns.
	_ = captureStderr(t, func() {
		if err := runGitFilterTrack(nil, []string{".env", "secrets/*.env"}); err != nil {
			t.Fatalf("track: %v", err)
		}
	})
	attrs, err := os.ReadFile(filepath.Join(root, ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(attrs), ".env filter=tvault") {
		t.Errorf(".gitattributes missing .env entry:\n%s", attrs)
	}

	// Re-tracking an existing pattern is a no-op (exercises the dedup path).
	_ = captureStderr(t, func() {
		if err := runGitFilterTrack(nil, []string{".env"}); err != nil {
			t.Fatalf("re-track: %v", err)
		}
	})

	// Status (text) should report installed + the tracked pattern. Success /
	// PrintKeyValue write to stdout.
	statusOut := captureStdout(t, func() {
		if err := runGitFilterStatus(nil, nil); err != nil {
			t.Fatalf("status: %v", err)
		}
	})
	if !strings.Contains(string(statusOut), "Filters installed") {
		t.Errorf("status output unexpected:\n%s", statusOut)
	}
	if !strings.Contains(string(statusOut), ".env") {
		t.Errorf("status output missing tracked pattern:\n%s", statusOut)
	}

	// Uninstall removes the filter section.
	_ = captureStderr(t, func() {
		if err := runGitFilterUninstall(nil, nil); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
	})
	if _, gerr := gitOutput(root, "config", "--get", "filter.tvault.clean"); gerr == nil {
		t.Error("filter.tvault.clean should be gone after uninstall")
	}
}

func TestRunGitFilterStatusJSON(t *testing.T) {
	gitFilterRepo(t)

	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	out := captureStdout(t, func() {
		if err := runGitFilterStatus(nil, nil); err != nil {
			t.Fatalf("status --json: %v", err)
		}
	})
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if _, ok := doc["installed"]; !ok {
		t.Error("status JSON missing 'installed' key")
	}
	if _, ok := doc["identity"]; !ok {
		t.Error("status JSON missing 'identity' key")
	}
}

// TestRunGitFilterCheckout exercises the resmudge loop: a tvault-tracked
// file that is already plaintext is left untouched (the ciphertext-version
// check short-circuits), and the command reports nothing to decrypt. We
// avoid relying on an installed `tvault` binary as the external smudge
// filter, which is not present in the test environment.
func TestRunGitFilterCheckout(t *testing.T) {
	root, rec := gitFilterRepo(t)

	if _, err := appendRecipients(root, []string{rec}); err != nil {
		t.Fatal(err)
	}

	// A plaintext file tracked by the tvault filter. resmudgeTracked must
	// see it is not a v2 file and leave it alone.
	plain := []byte("KEY=value\n")
	if werr := os.WriteFile(filepath.Join(root, ".env"), plain, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if werr := os.WriteFile(filepath.Join(root, ".gitattributes"),
		[]byte(".env filter=tvault\n"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	for _, args := range [][]string{
		{"add", ".env", ".gitattributes"},
		{"commit", "-m", "plaintext"},
	} {
		if _, gerr := gitOutput(root, args...); gerr != nil {
			t.Fatalf("git %v: %v", args, gerr)
		}
	}

	_ = captureStderr(t, func() {
		if err := runGitFilterCheckout(nil, nil); err != nil {
			t.Fatalf("checkout: %v", err)
		}
	})

	got, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("checkout should have left the plaintext file untouched, got %q", got)
	}
}
