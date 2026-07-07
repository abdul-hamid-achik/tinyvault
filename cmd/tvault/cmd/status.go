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
locked and agent_running so a non-interactive caller (e.g. Cortex) can
distinguish "vault reachable but locked" from "tvault broken/unreachable".`,
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
	// agentReachable observes the system (ignores --no-agent); a running
	// agent means value reads can be served without a passphrase prompt,
	// so the vault is effectively usable even though this handle is locked.
	agentRunning := agentReachable()
	// locked is "would a value read require a passphrase right now?": true
	// when this handle is not unlocked AND no agent is holding it unlocked.
	locked := !st.IsUnlocked && !agentRunning

	currentProject, _ := v.GetCurrentProject() //nolint:errcheck // empty string is fine as default
	projects, _ := v.ListProjects()            //nolint:errcheck // nil slice is fine as default

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"initialized":     true,
			"locked":          locked,
			"agent_running":   agentRunning,
			"vault_dir":       dir,
			"current_project": currentProject,
			"project_count":   len(projects),
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
	}
	PrintKeyValue("Agent", agentState)
	PrintKeyValue("Current project", currentProject)
	PrintKeyValue("Projects", fmt.Sprintf("%d", len(projects)))

	return nil
}
