package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a secret value",
	Long: `Get the value of a secret by key.

The decrypted value is printed to stdout. Messages go to stderr,
making this command pipe-friendly.

Examples:
  tvault get DATABASE_URL
  tvault get API_KEY --json
  DB_URL=$(tvault get DATABASE_URL)`,
	Aliases: []string{"g"},
	Args:    cobra.ExactArgs(1),
	RunE:    runGet,
}

func init() {
	rootCmd.AddCommand(getCmd)
}

func runGet(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)
	key := args[0]

	value, err := v.GetSecret(project, key)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{
			"key":   key,
			"value": value,
		})
	}

	fmt.Print(value)
	return nil
}
