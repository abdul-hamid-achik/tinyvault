package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var historyCmd = &cobra.Command{
	Use:     "history <key>",
	Aliases: []string{"versions", "hist"},
	Short:   "List the version history of a secret",
	Long: `List every version of a secret — newest at the bottom — with their
created/updated timestamps. Values are never shown (this is metadata only),
and the vault does not need to be unlocked.

Each overwrite of a secret archives the prior value as a version, so you can
inspect the timeline and roll back with 'tvault rollback'. Use
'tvault get <key> --version N' to print a specific historical value.

Examples:
  tvault history DATABASE_URL
  tvault history API_KEY --json`,
	Args: cobra.ExactArgs(1),
	RunE: runHistory,
}

func init() {
	rootCmd.AddCommand(historyCmd)
}

func runHistory(_ *cobra.Command, args []string) error {
	key := args[0]

	v, err := vault.Open(getVaultDir())
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", getVaultDir(), err)
	}
	defer v.Close()

	project := resolveProject(v, projectName)
	versions, err := v.ListSecretVersions(project, key)
	if err != nil {
		return fmt.Errorf("history for %q: %w", key, err)
	}
	recordAudit(v, "secret.read", "secret", key, map[string]any{"project": project, "source": "history"})

	if jsonOutput {
		type ver struct {
			Version   int    `json:"version"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}
		out := struct {
			Key      string `json:"key"`
			Project  string `json:"project"`
			Versions []ver  `json:"versions"`
		}{Key: key, Project: project}
		for _, sv := range versions {
			out.Versions = append(out.Versions, ver{
				Version:   sv.Version,
				CreatedAt: sv.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				UpdatedAt: sv.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			})
		}
		return writeJSON(out)
	}

	current := versions[len(versions)-1].Version
	fmt.Fprintf(os.Stderr, "Version history for %q (project %q):\n\n", key, project)
	fmt.Printf("%-9s %-22s %s\n", "VERSION", "CREATED", "UPDATED")
	for _, sv := range versions {
		marker := ""
		if sv.Version == current {
			marker = "  (current)"
		}
		fmt.Printf("v%-8d %-22s %s%s\n",
			sv.Version,
			sv.CreatedAt.Format("2006-01-02 15:04:05"),
			sv.UpdatedAt.Format("2006-01-02 15:04:05"),
			marker)
	}
	return nil
}
