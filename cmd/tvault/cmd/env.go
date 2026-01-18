package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	envFormat string
	envExport bool
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Export secrets as environment variables",
	Long: `Export all secrets as environment variables.

The output can be used with shell eval or saved to an .env file.

Examples:
  eval $(tvault env)
  tvault env --format=dotenv > .env
  source <(tvault env)`,
	RunE: runEnv,
}

func init() {
	rootCmd.AddCommand(envCmd)
	envCmd.Flags().StringVarP(&envFormat, "format", "f", "shell", "Output format: shell, dotenv, json")
	envCmd.Flags().BoolVarP(&envExport, "export", "e", true, "Include 'export' prefix (shell format only)")
}

func runEnv(cmd *cobra.Command, args []string) error {
	token := getToken()
	if token == "" {
		return fmt.Errorf("not logged in. Run 'tvault login' first")
	}

	project := getProject()
	if project == "" {
		return fmt.Errorf("no project selected. Run 'tvault use <project>' first")
	}

	client := NewClient(getAPIURL(), token)
	secrets, err := client.ExportSecrets(project)
	if err != nil {
		return fmt.Errorf("failed to export secrets: %w", err)
	}

	if len(secrets) == 0 {
		return nil
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	switch envFormat {
	case "shell":
		for _, k := range keys {
			v := secrets[k]
			escaped := escapeShellValue(v)
			if envExport {
				fmt.Printf("export %s=%s\n", k, escaped)
			} else {
				fmt.Printf("%s=%s\n", k, escaped)
			}
		}
	case "dotenv":
		for _, k := range keys {
			v := secrets[k]
			escaped := escapeDotenvValue(v)
			fmt.Printf("%s=%s\n", k, escaped)
		}
	case "json":
		fmt.Println("{")
		for i, k := range keys {
			v := secrets[k]
			escaped := escapeJSONValue(v)
			if i < len(keys)-1 {
				fmt.Printf("  \"%s\": \"%s\",\n", k, escaped)
			} else {
				fmt.Printf("  \"%s\": \"%s\"\n", k, escaped)
			}
		}
		fmt.Println("}")
	default:
		return fmt.Errorf("unknown format: %s", envFormat)
	}

	return nil
}

func escapeShellValue(s string) string {
	// Use single quotes and escape single quotes within
	if !strings.ContainsAny(s, "'\"\\$`\n\t ") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func escapeDotenvValue(s string) string {
	// Use double quotes if value contains special characters
	if !strings.ContainsAny(s, "\"\\$\n\t #") {
		return s
	}
	escaped := strings.ReplaceAll(s, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	escaped = strings.ReplaceAll(escaped, "\n", "\\n")
	return "\"" + escaped + "\""
}

func escapeJSONValue(s string) string {
	escaped := strings.ReplaceAll(s, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	escaped = strings.ReplaceAll(escaped, "\n", "\\n")
	escaped = strings.ReplaceAll(escaped, "\t", "\\t")
	return escaped
}
