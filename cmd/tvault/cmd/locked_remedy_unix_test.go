//go:build unix

package cmd

import (
	"errors"
	"strings"
	"testing"

	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// TestNonInteractiveWriteWithRunningAgentExplainsWhyTheAgentCannotHelp is the
// reported failure, reduced: an agent is running and serving this very vault,
// no TVAULT_PASSPHRASE is in the environment (the state of every child of
// `tvault run`, which strips them), and stdin is not a TTY.
//
// `tvault set` cannot succeed here — the agent protocol is read-only by design
// and never releases the KEK — so the contract under test is the diagnosis, not
// the write: the error must not send the user off to start an agent they are
// already running.
func TestNonInteractiveWriteWithRunningAgentExplainsWhyTheAgentCannotHelp(t *testing.T) {
	dir := shortAgentVault(t, "STRIPE_SECRET_KEY", "sk_test_123")
	stop := startTestAgentForCmd(t, dir)
	defer stop()

	// Model the child of `tvault run`: no unlock credential of any kind, and
	// no terminal to prompt at.
	t.Setenv("TVAULT_PASSPHRASE", "")
	t.Setenv(envIdentityKey, "")
	t.Setenv("TVAULT_NO_AGENT", "")
	withNonInteractiveStdin(t)

	// The agent really is serving this vault: reads are prompt-free. Without
	// this the assertions below would also pass for a dead socket.
	if val, ok := agentGetSecret(projectName, "STRIPE_SECRET_KEY"); !ok || val != "sk_test_123" {
		t.Fatalf("agent is not serving the vault under test (val=%q ok=%v)", val, ok)
	}

	err := runSet(nil, []string{"PROBE", "x"})
	if err == nil {
		t.Fatal("a write without any unlock credential must fail")
	}
	if !errors.Is(err, ivault.ErrLocked) {
		t.Fatalf("write must fail with the locked class (exit 3), got: %v", err)
	}
	if got := ExitCode(err); got != ExitLocked {
		t.Fatalf("ExitCode = %d, want %d", got, ExitLocked)
	}

	msg := err.Error()
	if strings.Contains(msg, "start 'tvault agent'") {
		t.Errorf("error tells the user to start the agent that is already running: %q", msg)
	}
	if !strings.Contains(msg, "reads only") {
		t.Errorf("error must say the running agent cannot serve this command: %q", msg)
	}
	if !strings.Contains(msg, "TVAULT_*") {
		t.Errorf("error must explain that a launched child inherits no TVAULT_* variable: %q", msg)
	}
}
