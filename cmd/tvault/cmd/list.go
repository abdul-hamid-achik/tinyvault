package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets in the current project",
	Long: `List all secret keys in the current project.

Use 'tvault get <key>' to retrieve a specific value.`,
	Aliases: []string{"ls"},
	RunE:    runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(_ *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)

	keys, err := v.ListSecrets(project)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	sort.Strings(keys)

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(keys)
	}

	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets found.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Add one with: tvault set KEY VALUE")
		return nil
	}

	for _, k := range keys {
		fmt.Println(k)
	}

	return nil
}
