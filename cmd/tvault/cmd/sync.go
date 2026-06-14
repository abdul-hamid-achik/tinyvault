package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	syncpkg "github.com/abdul-hamid-achik/tinyvault/internal/sync"
)

var (
	syncPath      string
	syncDirection string
	syncOverwrite bool
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Reconcile a .env file with the vault",
	Long: `Reconcile a .env file with the current vault project.

Direction:
  pull    Write vault -> .env (vault is source of truth). Creates the
          file if it does not exist. Existing keys in .env that are not
          in the vault are preserved.
  push    Write .env -> vault (.env is source of truth). Without
          --overwrite, existing vault keys are skipped.
  mirror  Reconcile in both directions. Conflicts (key present in both
          with different values) are reported and skipped.

Examples:
  tvault sync --direction pull --path .env
  tvault sync --direction push --path .env --overwrite
  tvault sync --direction mirror --path .env`,
	RunE: runSync,
}

func init() {
	rootCmd.AddCommand(syncCmd)
	// No -p shorthand: the root command reserves -p for --project.
	syncCmd.Flags().StringVar(&syncPath, "path", ".env", "Dotenv file path")
	syncCmd.Flags().StringVarP(&syncDirection, "direction", "d", "pull", "Direction: pull | push | mirror")
	syncCmd.Flags().BoolVar(&syncOverwrite, "overwrite", false, "Allow overwriting existing keys (push/mirror)")
}

func runSync(_ *cobra.Command, _ []string) error {
	dir, err := syncpkg.ParseDirection(syncDirection)
	if err != nil {
		return err
	}

	abs, err := filepath.Abs(syncPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)

	result, err := syncpkg.Sync(v, project, abs, dir, syncOverwrite)
	if err != nil {
		return err
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Direction: %s\n", result.Direction)
	fmt.Printf("Project:   %s\n", result.ProjectName)
	fmt.Printf("File:      %s\n", result.Path)
	if result.EnvCreated {
		fmt.Printf("           (file did not exist; created)\n")
	}
	fmt.Printf("Vault:     %d keys\n", result.VaultEntries)
	fmt.Printf("Env:       %d keys\n", result.EnvEntries)
	fmt.Println()

	printBucket := func(label string, keys []string) {
		if len(keys) == 0 {
			return
		}
		fmt.Printf("%s (%d):\n", label, len(keys))
		for _, k := range keys {
			fmt.Printf("  - %s\n", k)
		}
	}
	printBucket("Created", result.Created)
	printBucket("Updated", result.Updated)
	printBucket("Unchanged", result.Unchanged)
	printBucket("Skipped", result.Skipped)
	if len(result.Conflicts) > 0 {
		fmt.Printf("Conflicts (%d):\n", len(result.Conflicts))
		for _, c := range result.Conflicts {
			fmt.Printf("  - %s [resolution: %s]\n", c.Key, c.Resolution)
		}
	}

	return nil
}
