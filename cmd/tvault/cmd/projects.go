package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var projectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "Manage projects",
	Long:  "List, create, and delete projects.",
}

var projectsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all projects",
	RunE:  runProjectsList,
}

var projectsCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new project",
	Args:  cobra.ExactArgs(1),
	RunE:  runProjectsCreate,
}

var projectsDeleteCmd = &cobra.Command{
	Use:   "delete <project-id>",
	Short: "Delete a project",
	Long: `Delete a project and all its secrets.

By default, you will be prompted to confirm the deletion.
Use --yes or -y to skip the confirmation prompt.

WARNING: This action cannot be undone. All secrets in the project will be permanently deleted.`,
	Args: cobra.ExactArgs(1),
	RunE: runProjectsDelete,
}

var (
	projectDescription  string
	projectDeleteForce  bool
)

func init() {
	rootCmd.AddCommand(projectsCmd)
	projectsCmd.AddCommand(projectsListCmd)
	projectsCmd.AddCommand(projectsCreateCmd)
	projectsCmd.AddCommand(projectsDeleteCmd)

	projectsCreateCmd.Flags().StringVarP(&projectDescription, "description", "d", "", "Project description")
	projectsDeleteCmd.Flags().BoolVarP(&projectDeleteForce, "yes", "y", false, "Skip confirmation prompt")
}

func runProjectsList(cmd *cobra.Command, args []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	client := NewClient(getAPIURL(), token)
	projects, err := client.ListProjects()
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}

	if len(projects) == 0 {
		fmt.Println("No projects found.")
		fmt.Println()
		fmt.Println("Create one with: tvault projects create <name>")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tDESCRIPTION\tCREATED")
	for _, p := range projects {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.ID, p.Name, p.Description, p.CreatedAt)
	}
	w.Flush()

	return nil
}

func runProjectsCreate(cmd *cobra.Command, args []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	name := args[0]

	client := NewClient(getAPIURL(), token)
	project, err := client.CreateProject(name, projectDescription)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}

	fmt.Printf("Project '%s' created successfully!\n", project.Name)
	fmt.Printf("ID: %s\n", project.ID)
	fmt.Println()
	fmt.Printf("Use it with: tvault use %s\n", project.Name)

	return nil
}

func runProjectsDelete(cmd *cobra.Command, args []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	projectIDArg := args[0]

	// Prompt for confirmation unless --yes flag is set
	if !projectDeleteForce {
		Warning("This will permanently delete the project and all its secrets.")
		if !PromptConfirm(fmt.Sprintf("Delete project '%s'?", projectIDArg)) {
			Info("Cancelled")
			return nil
		}
	}

	client := NewClient(getAPIURL(), token)
	if err := client.DeleteProject(projectIDArg); err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}

	Success("Project deleted")

	// Clear current project if it was the one deleted
	if getProject() == projectIDArg {
		viper.Set("project", "")
		_ = viper.WriteConfigAs(getConfigPath())
	}

	return nil
}
