package cmd

import (
	"os"
	"strings"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
)

// noAgent disables agent routing for a single invocation (also via
// TVAULT_NO_AGENT). When set, get/env/run unlock the vault directly.
var noAgent bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&noAgent, "no-agent", false,
		"Bypass the tvault agent and unlock the vault directly")
}

func agentDisabled() bool {
	return noAgent || os.Getenv("TVAULT_NO_AGENT") != ""
}

// dialAgent returns a client if a usable agent is reachable, else (nil,false)
// so the caller falls back to direct vault access. Errors are swallowed: a
// missing/dead agent is the normal "go direct" path.
func dialAgent() (*agent.Client, bool) {
	if agentDisabled() {
		return nil, false
	}
	c, err := agent.Dial(getVaultDir(), 3*time.Second)
	if err != nil {
		return nil, false
	}
	// A capability token (for an agent started with --require-token) travels in
	// the environment; it is ignored by a default-mode agent.
	if tok := strings.TrimSpace(os.Getenv("TVAULT_AGENT_TOKEN")); tok != "" {
		c = c.WithToken(tok)
	}
	return c, true
}

// agentReachable reports whether a tvault agent socket is reachable under
// the configured vault dir, regardless of --no-agent / TVAULT_NO_AGENT. It
// is an observation about the system (used by `status --json`), not a
// routing decision, so it does NOT honor the no-agent bypass. A short
// timeout keeps `status` fast. Returns false on non-unix platforms.
func agentReachable() bool {
	c, err := agent.Dial(getVaultDir(), time.Second)
	if err != nil {
		return false
	}
	_ = c // Dial already opens+closes a probe connection; nothing to close.
	return true
}

// agentGetSecret tries to fetch one secret via the agent. The second return
// is false when the caller should fall back to a direct unlock (no agent, or
// the agent could not serve it).
func agentGetSecret(project, key string) (string, bool) {
	c, ok := dialAgent()
	if !ok {
		return "", false
	}
	val, err := c.Get(project, key)
	if err != nil {
		return "", false
	}
	return val, true
}

// agentAllSecrets tries to fetch a project's secrets via the agent, returning
// the resolved project name (the agent resolves an empty project to current).
func agentAllSecrets(project string) (secrets map[string]string, resolved string, ok bool) {
	c, dok := dialAgent()
	if !dok {
		return nil, "", false
	}
	m, p, err := c.GetAll(project)
	if err != nil {
		return nil, "", false
	}
	return m, p, true
}
