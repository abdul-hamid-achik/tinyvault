package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// captureStdoutErr runs fn with both os.Stdout and os.Stderr redirected to
// pipes and returns (stdout, stderr). Used for the non-interactive locked
// signal, where the contract is "JSON on stdout, nothing on stderr".
func captureStdoutErr(t *testing.T, fn func()) (stdout, stderr []byte) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()

	done := make(chan struct{})
	go func() {
		bufOut := make([]byte, 64*1024)
		bufErr := make([]byte, 64*1024)
		nOut, _ := rOut.Read(bufOut)
		nErr, _ := rErr.Read(bufErr)
		stdout = bufOut[:nOut]
		stderr = bufErr[:nErr]
		close(done)
	}()
	fn()
	_ = wOut.Close()
	_ = wErr.Close()
	<-done
	return stdout, stderr
}

// withNonInteractiveStdin replaces os.Stdin with an empty pipe so
// term.IsTerminal reports false (deterministic non-interactive mode).
func withNonInteractiveStdin(t *testing.T) {
	t.Helper()
	old := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		_ = r.Close()
		_ = w.Close()
	})
}

// setupLockedVault creates a vault in a short private temp dir, sets vaultDir,
// and ensures TVAULT_PASSPHRASE is empty so the vault is locked at rest for
// the caller. The short path keeps unix-domain socket tests below macOS's
// conservative sun_path limit.
func setupLockedVault(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tvl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	v, err := ivault.Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v.Close()
	oldVaultDir, oldProject, oldJSON, oldNames := vaultDir, projectName, jsonOutput, projectsNamesOnly
	t.Cleanup(func() {
		vaultDir, projectName, jsonOutput, projectsNamesOnly = oldVaultDir, oldProject, oldJSON, oldNames
	})
	vaultDir = dir
	projectName = ""
	jsonOutput = false
	projectsNamesOnly = false
	t.Setenv("TVAULT_PASSPHRASE", "")
	return dir
}

func TestRunProjectsListNamesOnlyJSON(t *testing.T) {
	dir := setupLockedVault(t)

	v := openTestVault(t, dir)
	if _, err := v.CreateProject("webapp", "owner@acme.io, prod-db.internal"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CreateProject("api", "secret description text"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	projectsNamesOnly = true
	jsonOutput = true

	out := captureStdout(t, func() {
		if err := runProjectsList(nil, nil); err != nil {
			t.Fatalf("runProjectsList --names-only --json on a locked vault: %v", err)
		}
	})

	var list []map[string]any
	if err := json.Unmarshal(out, &list); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if len(list) != 3 { // default + webapp + api
		t.Fatalf("expected 3 projects, got %d: %s", len(list), out)
	}
	for _, e := range list {
		name, _ := e["name"].(string)
		if name == "" {
			t.Errorf("entry missing name: %v", e)
		}
		if _, hasDesc := e["description"]; hasDesc {
			t.Errorf("names-only output must not include description, got %v for %q", e, name)
		}
		if _, hasCur := e["current"]; hasCur {
			t.Errorf("names-only output must not include current, got %v for %q", e, name)
		}
	}
}

func TestRunProjectsListNamesOnlyLockedText(t *testing.T) {
	dir := setupLockedVault(t)

	v := openTestVault(t, dir)
	if _, err := v.CreateProject("zzz", ""); err != nil {
		t.Fatal(err)
	}
	v.Close()

	projectsNamesOnly = true
	jsonOutput = false

	// No TVAULT_PASSPHRASE, stdin not a TTY — must still succeed (lock-free).
	out := captureStdout(t, func() {
		if err := runProjectsList(nil, nil); err != nil {
			t.Fatalf("runProjectsList --names-only on a locked vault: %v", err)
		}
	})
	names := strings.Fields(string(out))
	want := map[string]bool{"default": true, "zzz": true}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected name %q in %s", n, out)
		}
	}
	if !want["zzz"] || !contains(names, "zzz") {
		t.Errorf("expected zzz in output: %s", out)
	}
}

func TestRunListNamesOnlyJSON(t *testing.T) {
	dir := setupLockedVault(t)

	v := openTestVault(t, dir)
	for _, k := range []string{"DB_URL", "API_KEY", "STRIPE_KEY"} {
		if err := v.SetSecret("default", k, "x"); err != nil {
			t.Fatal(err)
		}
	}
	v.Close()

	listNamesOnly = true
	jsonOutput = true
	t.Cleanup(func() { listNamesOnly = false })

	out := captureStdout(t, func() {
		if err := runList(nil, nil); err != nil {
			t.Fatalf("runList --names-only --json on a locked vault: %v", err)
		}
	})
	var keys []string
	if err := json.Unmarshal(out, &keys); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	want := []string{"API_KEY", "DB_URL", "STRIPE_KEY"}
	if len(keys) != len(want) {
		t.Fatalf("got %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("keys[%d] = %q, want %q", i, keys[i], want[i])
		}
	}
}

func TestRunListNamesOnlyLockedNoPassphrase(t *testing.T) {
	dir := setupLockedVault(t)

	v := openTestVault(t, dir)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	listNamesOnly = true
	jsonOutput = false
	t.Cleanup(func() { listNamesOnly = false })

	// No passphrase, stdin not a TTY: names-only must NOT try to unlock.
	if err := runList(nil, nil); err != nil {
		t.Fatalf("runList --names-only must be lock-free, got: %v", err)
	}
}

func TestRunStatusJSONLockAgentFields(t *testing.T) {
	setupLockedVault(t)

	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })

	out := captureStdout(t, func() {
		if err := runStatus(nil, nil); err != nil {
			t.Fatalf("runStatus --json: %v", err)
		}
	})
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if doc["initialized"] != true {
		t.Errorf("initialized = %v, want true", doc["initialized"])
	}
	if doc["locked"] != true {
		t.Errorf("locked = %v, want true (no agent, fresh handle)", doc["locked"])
	}
	if doc["agent_running"] != false {
		t.Errorf("agent_running = %v, want false", doc["agent_running"])
	}
	if doc["agent_accessible"] != false {
		t.Errorf("agent_accessible = %v, want false", doc["agent_accessible"])
	}
	if _, ok := doc["project_count"]; !ok {
		t.Errorf("project_count missing from %s", out)
	}
}

func TestRunStatusDistinguishesTokenProtectedAgentAccess(t *testing.T) {
	dir := setupLockedVault(t)
	const (
		adminToken   = "test-admin-token"
		defaultToken = "test-default-token"
		stagingToken = "test-staging-token"
	)
	tokenFile := filepath.Join(t.TempDir(), "agent-tokens")
	if err := os.WriteFile(tokenFile, []byte(adminToken+"\n"+defaultToken+":default\n"+stagingToken+":staging\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := ivault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock("test-passphrase"); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	if _, err := v.CreateProject("staging", ""); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	if err := v.SetCurrentProject("staging"); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	kek, err := v.KEK()
	_ = v.Close()
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Start(agent.Options{
			Dir: dir, KEK: kek, Idle: 0, RequireToken: true, TokenFile: tokenFile,
			OnReady: func(string, int) { close(ready) },
		})
	}()
	select {
	case <-ready:
	case startErr := <-errCh:
		t.Fatalf("start token agent: %v", startErr)
	case <-time.After(3 * time.Second):
		t.Fatal("token agent did not become ready")
	}
	t.Cleanup(func() {
		if c, dialErr := agent.Dial(dir, time.Second); dialErr == nil {
			_ = c.WithToken(adminToken).Stop()
		}
		<-errCh
	})

	status := func() map[string]any {
		t.Helper()
		jsonOutput = true
		out := captureStdout(t, func() {
			if statusErr := runStatus(nil, nil); statusErr != nil {
				t.Fatalf("runStatus: %v", statusErr)
			}
		})
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("unmarshal status: %v\\n%s", err, out)
		}
		return doc
	}

	assertStatus := func(name, token, project string, accessible, locked bool) {
		t.Helper()
		t.Setenv("TVAULT_AGENT_TOKEN", token)
		projectName = project
		doc := status()
		if doc["agent_running"] != true || doc["agent_accessible"] != accessible || doc["locked"] != locked {
			t.Fatalf("%s status = %v, want running=true accessible=%t locked=%t", name, doc, accessible, locked)
		}
	}

	// No token and an invalid token cannot use the current staging project.
	assertStatus("token-less current", "", "", false, true)
	assertStatus("invalid current", "not-a-token", "", false, true)
	// The staging-scoped token works for the stored current project, but not
	// for the default project selected explicitly.
	assertStatus("staging-scoped current", stagingToken, "", true, false)
	assertStatus("staging-scoped default", stagingToken, "default", false, true)
	// The default-scoped token has the inverse behavior and proves the explicit
	// default fallback is checked without reading a secret.
	assertStatus("default-scoped current", defaultToken, "", false, true)
	assertStatus("default-scoped default", defaultToken, "default", true, false)
}

func TestNonInteractiveLockedSignalJSON(t *testing.T) {
	setupLockedVault(t)
	withNonInteractiveStdin(t)

	jsonOutput = true
	oldSilence := rootCmd.SilenceErrors
	t.Cleanup(func() {
		jsonOutput = false
		rootCmd.SilenceErrors = oldSilence
	})

	stdout, stderr := captureStdoutErr(t, func() {
		_, err := openAndUnlockVault()
		if err == nil {
			t.Fatal("expected an error from openAndUnlockVault with no passphrase and non-interactive stdin")
		}
		if !errors.Is(err, ivault.ErrLocked) {
			t.Fatalf("error must wrap vault.ErrLocked (exit 3), got: %v", err)
		}
		if got := ExitCode(err); got != ExitLocked {
			t.Fatalf("ExitCode = %d, want %d", got, ExitLocked)
		}
	})

	var doc map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &doc); err != nil {
		t.Fatalf("stdout must be the contract JSON, got parse error %v on %q", err, stdout)
	}
	if doc["error"] != "vault_locked" {
		t.Errorf("error = %v, want vault_locked (stdout=%q)", doc["error"], stdout)
	}
	if doc["locked"] != true {
		t.Errorf("locked = %v, want true (stdout=%q)", doc["locked"], stdout)
	}
	if len(stderr) != 0 {
		t.Errorf("stderr must be empty under --json, got %q", stderr)
	}
	if !rootCmd.SilenceErrors {
		t.Error("rootCmd.SilenceErrors must be set so cobra does not print to stderr")
	}
}

func TestNonInteractiveLockedSignalText(t *testing.T) {
	setupLockedVault(t)
	withNonInteractiveStdin(t)

	jsonOutput = false

	err := func() error {
		_, e := openAndUnlockVault()
		return e
	}()
	if err == nil {
		t.Fatal("expected an error from openAndUnlockVault with no passphrase and non-interactive stdin")
	}
	if !errors.Is(err, ivault.ErrLocked) {
		t.Fatalf("error must wrap vault.ErrLocked, got: %v", err)
	}
	if got := ExitCode(err); got != ExitLocked {
		t.Fatalf("ExitCode = %d, want %d (ExitLocked)", got, ExitLocked)
	}
	// Must not be the historical opaque passphrase-read error.
	if strings.Contains(err.Error(), "failed to read passphrase") {
		t.Errorf("non-interactive error must not be the old passphrase-read failure: %v", err)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
