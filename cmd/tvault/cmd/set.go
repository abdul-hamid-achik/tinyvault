package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

var (
	setStdin    bool
	setFromFile string
	setFromEnv  string
	setKey      string
)

var setCmd = &cobra.Command{
	Use:   "set <key> [value]",
	Short: "Set a secret value",
	Long: `Set a secret value.

If value is not provided, it will be read from stdin.
This is useful for setting multi-line secrets or piping values.

--from reads the value from a dotenv file (matching --key); use --key
when the source key name differs from the destination key.
--from-env reads from a dotenv file using the same key.

Examples:
  tvault set DATABASE_URL "postgres://..."
  echo "secret-value" | tvault set API_KEY
  tvault set GCP_CREDENTIALS --from-file credentials.json
  tvault set API_KEY --stdin
  tvault set DATABASE_URL --from-env .env
  tvault set DB_URL --from-env .env --key DATABASE_URL`,
	Aliases: []string{"s"},
	Args:    cobra.RangeArgs(1, 2),
	RunE:    runSet,
}

func init() {
	rootCmd.AddCommand(setCmd)
	setCmd.Flags().BoolVar(&setStdin, "stdin", false, "Read value from stdin")
	setCmd.Flags().StringVarP(&setFromFile, "from-file", "f", "", "Read value from file")
	setCmd.Flags().StringVar(&setFromEnv, "from-env", "", "Read value from a dotenv file")
	setCmd.Flags().StringVar(&setKey, "key", "", "Source key when --from-env is used (defaults to <key>)")
}

func runSet(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)
	key := args[0]
	var value string

	switch {
	case setFromFile != "":
		data, err := os.ReadFile(setFromFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		value = string(data)
	case setFromEnv != "":
		srcKey := setKey
		if srcKey == "" {
			srcKey = key
		}
		parsed, err := dotenv.ParseFile(setFromEnv)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", setFromEnv, err)
		}
		found := false
		for _, e := range parsed.Entries {
			if e.Key == srcKey {
				value = e.Value
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("key %q not found in %s", srcKey, setFromEnv)
		}
	case len(args) == 2:
		// Safe: Args is constrained by cobra to RangeArgs(1, 2), so
		// args[1] is guaranteed to exist whenever len(args) == 2.
		value = args[1] //nolint:gosec // bounds-checked by cobra Args
	case setStdin || !term.IsTerminal(int(os.Stdin.Fd())):
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
		value = strings.TrimSuffix(string(data), "\n")
	default:
		fmt.Fprint(os.Stderr, "Enter secret value: ")
		reader := bufio.NewReader(os.Stdin)
		v, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read value: %w", err)
		}
		value = strings.TrimSuffix(v, "\n")
	}

	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	if err := v.SetSecret(project, key, value); err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Secret '%s' set successfully\n", key)
	return nil
}
