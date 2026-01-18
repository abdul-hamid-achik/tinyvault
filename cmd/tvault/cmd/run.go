package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run <command> [args...]",
	Short: "Run a command with secrets as environment variables",
	Long: `Run a command with all project secrets injected as environment variables.

This is useful for running applications that need access to secrets
without exposing them in shell history or scripts.

Examples:
  tvault run npm start
  tvault run python manage.py runserver
  tvault run -- docker compose up`,
	DisableFlagParsing: true,
	RunE:               runRun,
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func runRun(_ *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("command is required")
	}

	// Handle -- separator
	if args[0] == "--" {
		args = args[1:]
		if len(args) == 0 {
			return fmt.Errorf("command is required after --")
		}
	}

	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	project := getProject()
	if project == "" {
		return fmt.Errorf("no project selected. Run 'tvault use <project>' first")
	}

	// Export all secrets
	client := NewClient(getAPIURL(), token)
	secrets, err := client.ExportSecrets(project)
	if err != nil {
		return fmt.Errorf("failed to export secrets: %w", err)
	}

	// Build environment
	env := os.Environ()
	for key, value := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Find the executable
	executable, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}

	// Create context for the command
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the command with context
	execCmd := exec.CommandContext(ctx, executable, args[1:]...)
	execCmd.Env = env
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the command
	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Forward signals to the child process
	go func() {
		sig := <-sigChan
		if execCmd.Process != nil {
			_ = execCmd.Process.Signal(sig)
		}
	}()

	// Wait for the command to finish
	if err := execCmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}
