package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status",
	Long: `Show vault status including path, lock state, agent state, current
project, and number of projects.

Status is lock-free: it opens the vault without unlocking, so it is safe to
run any time and never prompts for a passphrase. Under --json it reports
locked, agent_running, and agent_accessible for the selected project so a non-interactive caller
can distinguish "vault reachable but locked", "agent present but unavailable",
and "tvault broken/unreachable".`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{
				"initialized": false,
				"vault_dir":   dir,
			})
		}
		PrintKeyValue("Vault", dir)
		PrintKeyValue("Status", "not initialized")
		return nil
	}
	defer v.Close()

	st := v.Status()
	currentProject, _ := v.GetCurrentProject() //nolint:errcheck // empty string is fine as default
	projects, _ := v.ListProjects()            //nolint:errcheck // nil slice is fine as default
	// Match regular read routing: an explicit project wins, then the stored
	// current project, then the default project. The authorization probe below
	// is metadata-only and keeps status lock-free.
	effectiveProject := projectName
	if effectiveProject == "" {
		effectiveProject = currentProject
	}
	if effectiveProject == "" {
		effectiveProject = "default"
	}
	// agentReachable observes the system (ignores --no-agent). A live socket
	// does not necessarily mean this process can read through it: a
	// --require-token agent rejects clients without a valid token. Keep those
	// states separate so `locked` remains an honest answer for this process.
	agentRunning := agentReachable()
	canUseAgent := agentAccessible(effectiveProject)
	// locked is "would a value read require a passphrase right now?": true
	// when this handle is not unlocked AND no agent can serve this process.
	locked := !st.IsUnlocked && !canUseAgent

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"initialized":      true,
			"locked":           locked,
			"agent_running":    agentRunning,
			"agent_accessible": canUseAgent,
			"vault_dir":        dir,
			"current_project":  currentProject,
			"project_count":    len(projects),
		})
	}

	PrintKeyValue("Vault", dir)
	PrintKeyValue("Status", "initialized")
	lockState := "locked"
	if !locked {
		lockState = "unlocked"
	}
	PrintKeyValue("Lock", lockState)
	agentState := "not running"
	if agentRunning {
		agentState = "running"
		if !canUseAgent {
			agentState += " (access unavailable)"
		}
	}
	PrintKeyValue("Agent", agentState)
	PrintKeyValue("Current project", currentProject)
	PrintKeyValue("Projects", fmt.Sprintf("%d", len(projects)))

	return nil
}
