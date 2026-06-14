package cmd

import (
	"os"
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
	return c, true
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
