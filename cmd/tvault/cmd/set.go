package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
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
  cat credentials.json | tvault set GCP_CREDENTIALS`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runSet,
}

func init() {
	rootCmd.AddCommand(setCmd)
}

func runSet(cmd *cobra.Command, args []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	project := getProject()
	if project == "" {
		return fmt.Errorf("no project selected. Run 'tvault use <project>' first")
	}

	key := args[0]
	var value string

	if len(args) == 2 {
		value = args[1]
	} else {
		// Read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			// Interactive mode - prompt for value
			fmt.Print("Enter secret value: ")
			reader := bufio.NewReader(os.Stdin)
			v, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to read value: %w", err)
			}
			value = strings.TrimSuffix(v, "\n")
		} else {
			// Piped input
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read stdin: %w", err)
			}
			value = strings.TrimSuffix(string(data), "\n")
		}
	}

	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	client := NewClient(getAPIURL(), token)
	if err := client.SetSecret(project, key, value); err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	fmt.Printf("Secret '%s' set successfully\n", key)

	return nil
}
