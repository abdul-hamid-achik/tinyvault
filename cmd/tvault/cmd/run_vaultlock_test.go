package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"

	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// waitForFile polls for path until it exists or the deadline passes. It reports
// whether the file appeared, so callers can fail without hanging the suite.
func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// assertRunReleasesLock runs `tvault run` with a child that blocks until told to
// exit, and checks that the vault database is openable by another process while
// that child is alive. bbolt takes an exclusive process lock, so holding the
// vault open for the child's lifetime blocks every other tvault invocation on
// the machine — which is exactly what a long-lived child (an MCP server, a dev
// server) triggers.
func assertRunReleasesLock(t *testing.T, vaultPath string) {
	t.Helper()

	sync := t.TempDir()
	started := filepath.Join(sync, "started")
	proceed := filepath.Join(sync, "proceed")

	type probe struct {
		saw bool
		err error
	}
	result := make(chan probe, 1)

	go func() {
		// Always release the child, even on a failed probe, so runRun returns.
		defer func() { _ = os.WriteFile(proceed, []byte("go"), 0o600) }()

		if !waitForFile(started, 10*time.Second) {
			result <- probe{saw: false}
			return
		}
		other, err := ivault.Open(vaultPath)
		if err == nil {
			_ = other.Close()
		}
		result <- probe{saw: true, err: err}
	}()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	script := `: > "$1"; while [ ! -f "$2" ]; do sleep 0.01; done`
	if err := runRun(cmd, []string{"sh", "-c", script, "sh", started, proceed}); err != nil {
		t.Fatalf("runRun: %v", err)
	}

	got := <-result
	if !got.saw {
		t.Fatal("child never signaled start; cannot assert on the vault lock")
	}
	if got.err != nil {
		t.Fatalf("vault was still locked while the child process ran: %v", got.err)
	}
}

// TestRunSelectedReleasesVaultLockBeforeChildStarts covers the --only path,
// which resolves secrets through its own vault handle.
func TestRunSelectedReleasesVaultLockBeforeChildStarts(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	resetRunLeastPrivilegeFlags(t)

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "CHALUPA_TOKEN", "selected"); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	runOnly = []string{"CHALUPA_TOKEN"}
	assertRunReleasesLock(t, vaultPath)
}

// TestRunAllReleasesVaultLockBeforeChildStarts covers the unselected path, so a
// future refactor cannot reintroduce the leak there either.
func TestRunAllReleasesVaultLockBeforeChildStarts(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	resetRunLeastPrivilegeFlags(t)

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "CHALUPA_TOKEN", "selected"); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	assertRunReleasesLock(t, vaultPath)
}
