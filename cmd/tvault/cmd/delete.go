package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	deleteForce bool
)

var deleteCmd = &cobra.Command{
	Use:   "delete <key>",
	Short: "Delete a secret",
	Long: `Delete a secret from the current project.

By default, you will be prompted to confirm the deletion.
Use --yes or -y to skip the confirmation prompt.`,
	Aliases: []string{"rm", "remove"},
	Args:    cobra.ExactArgs(1),
	RunE:    runDelete,
}

func init() {
	rootCmd.AddCommand(deleteCmd)

	deleteCmd.Flags().BoolVarP(&deleteForce, "yes", "y", false, "Skip confirmation prompt")
}

func runDelete(_ *cobra.Command, args []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	project := getProject()
	if project == "" {
		return fmt.Errorf("no project selected. Run 'tvault use <project>' first")
	}

	key := args[0]

	// Prompt for confirmation unless --yes flag is set
	if !deleteForce {
		if !PromptConfirm(fmt.Sprintf("Delete secret '%s'?", key)) {
			Info("Canceled")
			return nil
		}
	}

	client := NewClient(getAPIURL(), token)
	if err := client.DeleteSecret(project, key); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	Success("Secret '%s' deleted", key)

	return nil
}
