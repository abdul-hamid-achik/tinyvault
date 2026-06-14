package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rollbackToVersion int

var rollbackCmd = &cobra.Command{
	Use:   "rollback <key> --to <version>",
	Short: "Restore an earlier version of a secret",
	Long: `Restore the value of an earlier version of a secret as a new current
version. Rollback is non-destructive: the value being replaced is archived as
its own version and stays recoverable, and version numbers are never reused
(rolling back to v2 creates a new v4 holding v2's value).

See the available versions with 'tvault history <key>'.

Examples:
  tvault rollback DATABASE_URL --to 2
  tvault rollback API_KEY --to 1 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runRollback,
}

func init() {
	rootCmd.AddCommand(rollbackCmd)
	rollbackCmd.Flags().IntVar(&rollbackToVersion, "to", 0, "Version number to restore (required)")
}

func runRollback(_ *cobra.Command, args []string) error {
	key := args[0]
	if rollbackToVersion <= 0 {
		return fmt.Errorf("--to <version> is required (see `tvault history %s`)", key)
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)
	newVersion, err := v.RollbackSecret(project, key, rollbackToVersion)
	if err != nil {
		return fmt.Errorf("rollback %q to v%d: %w", key, rollbackToVersion, err)
	}
	recordAudit(v, "secret.rollback", "secret", key, map[string]any{
		"project":      project,
		"from_version": rollbackToVersion,
		"new_version":  newVersion,
	})

	if jsonOutput {
		return writeJSON(map[string]any{
			"key":              key,
			"project":          project,
			"rolled_back_from": rollbackToVersion,
			"new_version":      newVersion,
		})
	}
	fmt.Fprintf(os.Stderr, "%s: rolled back to v%d (new version v%d)\n", key, rollbackToVersion, newVersion)
	return nil
}
