package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

var getFromFile string

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a secret value",
	Long: `Get the value of a secret by key.

The decrypted value is printed to stdout. Messages go to stderr,
making this command pipe-friendly.

When --from is used, the value is read from a dotenv file instead of
the vault. The file does not need to be unlocked; the value is read
verbatim (no interpolation). Use tvault run for ${tvault://...} resolution.

Examples:
  tvault get DATABASE_URL
  tvault get API_KEY --json
  tvault get DATABASE_URL --from .env
  DB_URL=$(tvault get DATABASE_URL)`,
	Aliases: []string{"g"},
	Args:    cobra.ExactArgs(1),
	RunE:    runGet,
}

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().StringVarP(&getFromFile, "from", "", "", "Read value from a dotenv file instead of the vault")
}

func runGet(_ *cobra.Command, args []string) error {
	key := args[0]

	if getFromFile != "" {
		value, err := getFromDotenv(getFromFile, key)
		if err != nil {
			return err
		}
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]string{"key": key, "value": value, "source": getFromFile})
		}
		fmt.Print(value)
		return nil
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)

	value, err := v.GetSecret(project, key)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}
	recordAudit(v, "secret.read", "secret", key, map[string]any{"project": project})

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

// getFromDotenv reads a single key from a dotenv file without touching
// the vault. The file name still goes through the safety allowlist so
// that a malicious path like `~/.bashrc` cannot be smuggled in.
func getFromDotenv(path, key string) (string, error) {
	parsed, err := dotenv.ParseFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", path, err)
	}
	for _, e := range parsed.Entries {
		if e.Key == key {
			return e.Value, nil
		}
	}
	return "", fmt.Errorf("key %q not found in %s", key, path)
}
