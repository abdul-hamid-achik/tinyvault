package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets in the current project",
	Long: `List all secret keys in the current project.

Secret values are not displayed for security.
Use 'tvault get <key>' to retrieve a specific value.`,
	Aliases: []string{"ls"},
	RunE:    runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(_ *cobra.Command, _ []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	project := getProject()
	if project == "" {
		return fmt.Errorf("no project selected. Run 'tvault use <project>' first")
	}

	client := NewClient(getAPIURL(), token)
	secrets, err := client.ListSecrets(project)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if len(secrets) == 0 {
		fmt.Println("No secrets found.")
		fmt.Println()
		fmt.Println("Add one with: tvault set KEY VALUE")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tVERSION\tUPDATED")
	for _, s := range secrets {
		fmt.Fprintf(w, "%s\t%d\t%s\n", s.Key, s.Version, s.UpdatedAt)
	}
	w.Flush()

	return nil
}
