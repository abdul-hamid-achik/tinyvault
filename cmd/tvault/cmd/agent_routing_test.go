//go:build unix

package cmd

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// shortAgentVault creates a vault in a SHORT temp dir (t.TempDir embeds the
// long test name and can push the agent socket past the ~104-byte sun_path
// limit), sets it as the active vault dir, and stores one secret.
func shortAgentVault(t *testing.T, key, value string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tvc")
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
	if err := v.SetSecret("default", key, value); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	oldDir, oldProj, oldJSON, oldNoAgent := vaultDir, projectName, jsonOutput, noAgent
	vaultDir, projectName, jsonOutput, noAgent = dir, "", false, false
	t.Setenv("TVAULT_PASSPHRASE", "test-passphrase")
	t.Cleanup(func() { vaultDir, projectName, jsonOutput, noAgent = oldDir, oldProj, oldJSON, oldNoAgent })
	return dir
}

func startTestAgentForCmd(t *testing.T, dir string) func() {
	t.Helper()
	v, err := ivault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatal(err)
	}
	kek, err := v.KEK()
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Start(agent.Options{
			Dir: dir, KEK: kek, Project: "default", Idle: 0,
			OnReady: func(string, int) { close(ready) },
		})
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("agent start: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not become ready")
	}
	return func() {
		if c, e := agent.Dial(dir, time.Second); e == nil {
			_ = c.Stop()
		}
		<-errCh
	}
}

func TestAgentRoutingFastPath(t *testing.T) {
	dir := shortAgentVault(t, "K", "agent-value")
	stop := startTestAgentForCmd(t, dir)
	defer stop()

	val, ok := agentGetSecret(projectName, "K")
	if !ok || val != "agent-value" {
		t.Errorf("agentGetSecret via agent = %q ok=%v", val, ok)
	}
	secrets, proj, ok := agentAllSecrets(projectName)
	if !ok || secrets["K"] != "agent-value" || proj != "default" {
		t.Errorf("agentAllSecrets via agent = %v proj=%q ok=%v", secrets, proj, ok)
	}
}

func TestAgentRoutingDisabledByFlag(t *testing.T) {
	dir := shortAgentVault(t, "K", "v")
	stop := startTestAgentForCmd(t, dir)
	defer stop()

	old := noAgent
	noAgent = true
	defer func() { noAgent = old }()
	if _, ok := agentGetSecret(projectName, "K"); ok {
		t.Error("--no-agent must bypass the agent")
	}
}

func TestAgentRoutingFallbackWhenNoAgent(t *testing.T) {
	shortAgentVault(t, "K", "v")
	// No agent started → routing helpers report "go direct".
	if _, ok := agentGetSecret(projectName, "K"); ok {
		t.Error("no agent → agentGetSecret should return ok=false")
	}
	if _, _, ok := agentAllSecrets(projectName); ok {
		t.Error("no agent → agentAllSecrets should return ok=false")
	}
}

func TestAgentRoutingDisabledByEnv(t *testing.T) {
	dir := shortAgentVault(t, "K", "v")
	stop := startTestAgentForCmd(t, dir)
	defer stop()

	t.Setenv("TVAULT_NO_AGENT", "1")
	if _, ok := agentGetSecret(projectName, "K"); ok {
		t.Error("TVAULT_NO_AGENT must bypass the agent")
	}
	if _, _, ok := agentAllSecrets(projectName); ok {
		t.Error("TVAULT_NO_AGENT must bypass the agent for getall")
	}
}

// TestGetVersionBypassesAgent proves `get --version N` skips the agent (which
// only serves the current value) and reads the historical version directly.
func TestGetVersionBypassesAgent(t *testing.T) {
	dir := shortAgentVault(t, "K", "old") // v1 = "old"
	// Bump to v2 = "new" via a direct open before starting the agent.
	v, err := ivault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if uerr := v.Unlock("test-passphrase"); uerr != nil {
		t.Fatal(uerr)
	}
	if serr := v.SetSecret("default", "K", "new"); serr != nil {
		t.Fatal(serr)
	}
	_ = v.Close()

	stop := startTestAgentForCmd(t, dir) // agent serves current = "new"
	defer stop()

	oldV, oldFrom := getVersion, getFromFile
	getVersion, getFromFile = 1, ""
	defer func() { getVersion, getFromFile = oldV, oldFrom }()

	out := captureStdout(t, func() {
		if err := runGet(nil, []string{"K"}); err != nil {
			t.Fatalf("get --version 1: %v", err)
		}
	})
	if got := string(out); got != "old" {
		t.Errorf("get --version 1 = %q, want \"old\" (agent must be bypassed for historical reads)", got)
	}
}

// TestGetGroupBypassesAgentFastPath proves environment-group reads never use
// the agent's direct-project get operation. The direct path resolves an empty
// project to the current project, which is not necessarily the project mapped
// to the requested group/environment.
func TestGetGroupBypassesAgentFastPath(t *testing.T) {
	const (
		key             = "SHARED_KEY"
		currentValue    = "current-project-value"
		groupValue      = "group-project-value"
		groupProject    = "preview-project"
		groupName       = "webapp"
		environmentName = "preview"
	)

	dir := shortAgentVault(t, key, currentValue)
	v, err := ivault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock("test-passphrase"); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	if _, err := v.CreateProject(groupProject, ""); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	if err := v.SetSecret(groupProject, key, groupValue); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	if _, err := v.CreateEnvGroup(groupName, "", []ivault.EnvGroupEntry{
		{Name: environmentName, Project: groupProject},
	}, false); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	if err := v.SetCurrentProject("default"); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	stop := startTestAgentForCmd(t, dir)
	defer stop()

	oldVersion, oldFrom := getVersion, getFromFile
	oldGroup, oldEnv, oldShowSource := getGroup, getEnv, getShowSource
	getVersion, getFromFile = 0, ""
	getGroup, getEnv, getShowSource = "", "", false
	t.Cleanup(func() {
		getVersion, getFromFile = oldVersion, oldFrom
		getGroup, getEnv, getShowSource = oldGroup, oldEnv, oldShowSource
	})

	// Model a non-interactive client that has access only to the agent socket.
	t.Setenv("TVAULT_PASSPHRASE", "")
	t.Setenv(envIdentityKey, "")
	t.Setenv("TVAULT_NO_AGENT", "")
	withNonInteractiveStdin(t)

	// Direct-project get must retain its existing prompt-free agent behavior.
	var directErr error
	directOut := captureStdout(t, func() {
		directErr = runGet(nil, []string{key})
	})
	if directErr != nil {
		t.Fatalf("direct get through agent failed: %v", directErr)
	}
	if string(directOut) != currentValue {
		t.Fatal("direct get through agent returned an unexpected value")
	}

	getGroup, getEnv = groupName, environmentName
	var groupErr error
	groupOut := captureStdout(t, func() {
		groupErr = runGet(nil, []string{key})
	})
	if groupErr == nil {
		t.Fatal("group/env get unexpectedly succeeded without an unlock credential")
	}
	if !errors.Is(groupErr, ivault.ErrLocked) {
		t.Fatalf("group/env get returned the wrong error class: %v", groupErr)
	}
	if len(groupOut) != 0 {
		t.Fatal("group/env get emitted a project value instead of failing locked")
	}

	// With an explicit unlock credential, the same request follows normal
	// inheritance resolution and returns the environment project's value.
	t.Setenv("TVAULT_PASSPHRASE", "test-passphrase")
	var resolvedErr error
	resolvedOut := captureStdout(t, func() {
		resolvedErr = runGet(nil, []string{key})
	})
	if resolvedErr != nil {
		t.Fatalf("group/env get with unlock credential failed: %v", resolvedErr)
	}
	if string(resolvedOut) != groupValue {
		t.Fatal("group/env get resolved an unexpected project value")
	}
}
