package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status",
	Long:  "Show vault status including path, lock state, current project, and number of projects.",
	RunE:  runStatus,
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

	currentProject, _ := v.GetCurrentProject()
	projects, _ := v.ListProjects()

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"initialized":     true,
			"vault_dir":       dir,
			"current_project": currentProject,
			"project_count":   len(projects),
		})
	}

	PrintKeyValue("Vault", dir)
	PrintKeyValue("Status", "initialized")
	PrintKeyValue("Current project", currentProject)
	PrintKeyValue("Projects", fmt.Sprintf("%d", len(projects)))

	return nil
}
