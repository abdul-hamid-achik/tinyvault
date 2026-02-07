package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var useCmd = &cobra.Command{
	Use:   "use <project>",
	Short: "Select a project to use",
	Long: `Select a project to use for subsequent commands.

This is a shorthand for 'tvault projects use'.`,
	Args: cobra.ExactArgs(1),
	RunE: runUse,
}

func init() {
	rootCmd.AddCommand(useCmd)
}

func runUse(_ *cobra.Command, args []string) error {
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
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "You can now manage secrets:")
	fmt.Fprintln(os.Stderr, "  tvault set KEY VALUE    Set a secret")
	fmt.Fprintln(os.Stderr, "  tvault get KEY          Get a secret")
	fmt.Fprintln(os.Stderr, "  tvault list             List all secrets")
	fmt.Fprintln(os.Stderr, "  tvault run <command>    Run with secrets as env vars")

	return nil
}
