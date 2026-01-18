package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var useCmd = &cobra.Command{
	Use:   "use <project>",
	Short: "Select a project to use",
	Long: `Select a project to use for subsequent commands.

The project can be specified by name or ID.`,
	Args: cobra.ExactArgs(1),
	RunE: runUse,
}

func init() {
	rootCmd.AddCommand(useCmd)
}

func runUse(_ *cobra.Command, args []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	projectRef := args[0]

	// Validate the project exists
	client := NewClient(getAPIURL(), token)
	projects, err := client.ListProjects()
	if err != nil {
		return fmt.Errorf("failed to verify project: %w", err)
	}

	var found *Project
	for _, p := range projects {
		if p.ID == projectRef || p.Name == projectRef {
			found = &p
			break
		}
	}

	if found == nil {
		return fmt.Errorf("project '%s' not found", projectRef)
	}

	// Save the project
	viper.Set("project", found.ID)
	if err := viper.WriteConfigAs(getConfigPath()); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Now using project: %s (%s)\n", found.Name, found.ID)
	fmt.Println()
	fmt.Println("You can now manage secrets:")
	fmt.Println("  tvault set KEY VALUE    Set a secret")
	fmt.Println("  tvault get KEY          Get a secret")
	fmt.Println("  tvault list             List all secrets")
	fmt.Println("  tvault run <command>    Run with secrets as env vars")

	return nil
}
