package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var projectsCmd = &cobra.Command{
	Use:     "projects",
	Aliases: []string{"project", "p"},
	Short:   "Manage projects",
	Long:    "List, create, and delete projects.",
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
	Use:   "delete <name>",
	Short: "Delete a project",
	Long: `Delete a project and all its secrets.

By default, you will be prompted to confirm the deletion.
Use --yes or -y to skip the confirmation prompt.

WARNING: This action cannot be undone.`,
	Args: cobra.ExactArgs(1),
	RunE: runProjectsDelete,
}

var projectsUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the active project",
	Args:  cobra.ExactArgs(1),
	RunE:  runProjectsUse,
}

var (
	projectDescription string
	projectDeleteForce bool
	projectsNamesOnly  bool
)

func init() {
	rootCmd.AddCommand(projectsCmd)
	projectsCmd.AddCommand(projectsListCmd)
	projectsCmd.AddCommand(projectsCreateCmd)
	projectsCmd.AddCommand(projectsDeleteCmd)
	projectsCmd.AddCommand(projectsUseCmd)

	projectsCreateCmd.Flags().StringVarP(&projectDescription, "description", "d", "", "Project description")
	projectsDeleteCmd.Flags().BoolVarP(&projectDeleteForce, "yes", "y", false, "Skip confirmation prompt")
	projectsListCmd.Flags().BoolVar(&projectsNamesOnly, "names-only", false,
		"List project names only (no descriptions); lock-free — works on a locked vault")
}

func runProjectsList(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()

	// --names-only is value-free and lock-free: project names live in the
	// clear project_names index, so we open without unlocking. This lets an
	// agent (e.g. Cortex) enumerate project names without a passphrase and
	// without ever seeing descriptions (which can hold sensitive free text).
	if projectsNamesOnly {
		v, err := vault.Open(dir)
		if err != nil {
			return fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", dir, err)
		}
		defer v.Close()
		projects, err := v.ListProjects()
		if err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
		}
		names := make([]string, 0, len(projects))
		for _, p := range projects {
			names = append(names, p.Name)
		}
		sort.Strings(names)
		if jsonOutput {
			out := make([]map[string]string, 0, len(names))
			for _, n := range names {
				out = append(out, map[string]string{"name": n})
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	projects, err := v.ListProjects()
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}

	currentProject, _ := v.GetCurrentProject() //nolint:errcheck // empty string is fine as default

	if jsonOutput {
		type projectJSON struct {
			Name        string `json:"name"`
			Description string `json:"description,omitempty"`
			Current     bool   `json:"current,omitempty"`
		}
		var list []projectJSON
		for _, p := range projects {
			list = append(list, projectJSON{
				Name:        p.Name,
				Description: p.Description,
				Current:     p.Name == currentProject,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(list)
	}

	if len(projects) == 0 {
		fmt.Fprintln(os.Stderr, "No projects found.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Create one with: tvault projects create <name>")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tDESCRIPTION\tCURRENT")
	for _, p := range projects {
		current := ""
		if p.Name == currentProject {
			current = "*"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Description, current)
	}
	_ = w.Flush()

	return nil
}

func runProjectsCreate(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	name := args[0]
	project, err := v.CreateProject(name, projectDescription)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}
	recordAudit(v, "project.create", "project", project.Name, nil)

	Success("Project '%s' created", project.Name)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Use it with: tvault use %s\n", project.Name)

	return nil
}

func runProjectsDelete(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	name := args[0]

	if !projectDeleteForce {
		Warning("This will permanently delete the project and all its secrets.")
		if !PromptConfirm(fmt.Sprintf("Delete project '%s'?", name)) {
			Info("Canceled")
			return nil
		}
	}

	if err := v.DeleteProject(name); err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}
	recordAudit(v, "project.delete", "project", name, nil)

	Success("Project '%s' deleted", name)
	return nil
}

func runProjectsUse(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	name := args[0]

	if err := v.SetCurrentProject(name); err != nil {
		return fmt.Errorf("project '%s' not found", name)
	}

	fmt.Fprintf(os.Stderr, "Now using project: %s\n", name)
	return nil
}
