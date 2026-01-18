package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	importOverwrite bool
	importDryRun    bool
)

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import secrets from a .env file",
	Long: `Import secrets from a .env file into the current project.

Each line in the file should be in KEY=VALUE format.
Lines starting with # are treated as comments and ignored.
Empty lines are also ignored.

Examples:
  tvault import .env
  tvault import .env.production
  tvault import secrets.env --dry-run
  tvault import .env --overwrite`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(importCmd)

	importCmd.Flags().BoolVar(&importOverwrite, "overwrite", false, "Overwrite existing secrets")
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Show what would be imported without making changes")
}

func runImport(cmd *cobra.Command, args []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	project := getProject()
	if project == "" {
		return fmt.Errorf("no project selected. Run 'tvault use <project>' first")
	}

	filePath := args[0]

	// Parse the .env file
	secrets, err := parseEnvFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse file: %w", err)
	}

	if len(secrets) == 0 {
		Warning("No secrets found in %s", filePath)
		return nil
	}

	client := NewClient(getAPIURL(), token)

	// Get existing secrets to check for conflicts
	existingSecrets, err := client.ListSecrets(project)
	if err != nil {
		return fmt.Errorf("failed to list existing secrets: %w", err)
	}

	existingKeys := make(map[string]bool)
	for _, s := range existingSecrets {
		existingKeys[s.Key] = true
	}

	// Process each secret
	var imported, skipped, overwritten int

	if importDryRun {
		Info("Dry run - no changes will be made")
		fmt.Println()
	}

	for key, value := range secrets {
		exists := existingKeys[key]

		if exists && !importOverwrite {
			if importDryRun {
				fmt.Printf("  %s %s (would skip - already exists)\n", WarningIcon(), key)
			} else {
				fmt.Printf("  %s %s (skipped - already exists)\n", WarningIcon(), key)
			}
			skipped++
			continue
		}

		if importDryRun {
			if exists {
				fmt.Printf("  %s %s (would overwrite)\n", SuccessIcon(), key)
			} else {
				fmt.Printf("  %s %s (would create)\n", SuccessIcon(), key)
			}
		} else {
			if err := client.SetSecret(project, key, value); err != nil {
				Error("Failed to set %s: %v", key, err)
				continue
			}

			if exists {
				fmt.Printf("  %s %s (overwritten)\n", SuccessIcon(), key)
				overwritten++
			} else {
				fmt.Printf("  %s %s\n", SuccessIcon(), key)
				imported++
			}
		}
	}

	fmt.Println()

	if importDryRun {
		Info("Would import %d secret(s), skip %d existing", len(secrets)-skipped, skipped)
	} else {
		if imported > 0 || overwritten > 0 {
			Success("Imported %d secret(s)", imported+overwritten)
		}
		if skipped > 0 {
			Info("Skipped %d existing secret(s). Use --overwrite to replace them.", skipped)
		}
	}

	return nil
}

// parseEnvFile reads a .env file and returns a map of key-value pairs
func parseEnvFile(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	secrets := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE format
		idx := strings.Index(line, "=")
		if idx == -1 {
			Warning("Line %d: Invalid format (missing '='): %s", lineNum, line)
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Remove surrounding quotes if present
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		// Handle escape sequences in double-quoted values
		value = strings.ReplaceAll(value, "\\n", "\n")
		value = strings.ReplaceAll(value, "\\t", "\t")
		value = strings.ReplaceAll(value, "\\\"", "\"")

		if key == "" {
			Warning("Line %d: Empty key", lineNum)
			continue
		}

		secrets[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
}
