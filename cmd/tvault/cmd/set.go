package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	setStdin    bool
	setFromFile string
)

var setCmd = &cobra.Command{
	Use:   "set <key> [value]",
	Short: "Set a secret value",
	Long: `Set a secret value.

If value is not provided, it will be read from stdin.
This is useful for setting multi-line secrets or piping values.

Examples:
  tvault set DATABASE_URL "postgres://..."
  echo "secret-value" | tvault set API_KEY
  tvault set GCP_CREDENTIALS --from-file credentials.json
  tvault set API_KEY --stdin`,
	Aliases: []string{"s"},
	Args:    cobra.RangeArgs(1, 2),
	RunE:    runSet,
}

func init() {
	rootCmd.AddCommand(setCmd)
	setCmd.Flags().BoolVar(&setStdin, "stdin", false, "Read value from stdin")
	setCmd.Flags().StringVarP(&setFromFile, "from-file", "f", "", "Read value from file")
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
	case len(args) == 2:
		value = args[1]
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
