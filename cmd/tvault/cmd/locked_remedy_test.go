package cmd

import (
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
)

// The agent is a read accelerator, not an unlock service: its protocol has no
// write operation and it never releases the KEK. Advice that tells a user to
// start (or keep) an agent in order to satisfy a command that needs the key is
// therefore wrong, and wrong in the expensive direction — it points at the
// socket when the fix is to supply a credential.
func TestLockedRemedyWithRunningAgentDoesNotAdviseTheAgent(t *testing.T) {
	got := lockedRemedy(true)

	if strings.Contains(got, "start 'tvault agent'") || strings.Contains(got, "starting 'tvault agent'") {
		t.Errorf("remedy tells a user with a running agent to start one: %q", got)
	}
	for _, want := range []string{
		"reads only", // says what the running agent can and cannot do
		"needs the passphrase itself",
		"TVAULT_PASSPHRASE", // and what would actually work
	} {
		if !strings.Contains(got, want) {
			t.Errorf("remedy is missing %q: %q", want, got)
		}
	}
}

func TestLockedRemedyWithoutAgentQualifiesTheAgentSuggestion(t *testing.T) {
	got := lockedRemedy(false)

	if !strings.Contains(got, "TVAULT_PASSPHRASE") {
		t.Errorf("remedy must name the credential that works: %q", got)
	}
	if !agent.Supported() {
		if strings.Contains(got, "tvault agent") {
			t.Errorf("remedy suggests the agent on a platform without one: %q", got)
		}
		return
	}
	if !strings.Contains(got, "starting 'tvault agent'") {
		t.Errorf("remedy should still offer the agent when none is running: %q", got)
	}
	// Offering it unqualified is how the misleading advice got there in the
	// first place: an agent never makes a write prompt-free.
	if !strings.Contains(got, "never unlocks a write") {
		t.Errorf("agent suggestion must be qualified as reads-only: %q", got)
	}
}

// Every remedy must mention the child-process rule, because the failure mode
// people actually hit is a tvault nested inside `tvault run` (or MCP exec),
// where the parent's TVAULT_PASSPHRASE is deliberately stripped and no amount
// of exporting it in the outer shell reaches the child.
func TestLockedRemedyAlwaysExplainsStrippedChildEnvironment(t *testing.T) {
	for _, agentRunning := range []bool{true, false} {
		got := lockedRemedy(agentRunning)
		if !strings.Contains(got, "TVAULT_*") || !strings.Contains(got, "tvault run") {
			t.Errorf("remedy (agentRunning=%v) must explain the stripped child env: %q", agentRunning, got)
		}
	}
}
