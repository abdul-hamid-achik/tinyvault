package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	exportFormat  string
	exportOutput  string
	exportK8sName string
	exportK8sNs   string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all secrets",
	Long: `Export all secrets from the current project in various formats.

Examples:
  tvault export --format dotenv > .env
  tvault export --format json -o secrets.json
  tvault export --format yaml
  tvault export --format k8s-secret --name my-secrets`,
	RunE: runExport,
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "dotenv", "Output format: dotenv, json, yaml, k8s-secret")
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Write to file instead of stdout")
	exportCmd.Flags().StringVar(&exportK8sName, "name", "", "Kubernetes Secret name (required for k8s-secret format)")
	exportCmd.Flags().StringVar(&exportK8sNs, "namespace", "default", "Kubernetes namespace (k8s-secret format)")
}

func runExport(_ *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)

	secrets, err := v.GetAllSecrets(project)
	if err != nil {
		return fmt.Errorf("failed to get secrets: %w", err)
	}

	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets to export.")
		return nil
	}

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var output string
	switch exportFormat {
	case "dotenv":
		var lines []string
		for _, k := range keys {
			escaped := escapeDotenvValue(secrets[k])
			lines = append(lines, fmt.Sprintf("%s=%s", k, escaped))
		}
		output = strings.Join(lines, "\n") + "\n"
	case "json":
		var lines []string
		lines = append(lines, "{")
		for i, k := range keys {
			escaped := escapeJSONValue(secrets[k])
			comma := ","
			if i == len(keys)-1 {
				comma = ""
			}
			lines = append(lines, fmt.Sprintf("  \"%s\": \"%s\"%s", k, escaped, comma)) //nolint:gocritic // sprintfQuotedString: %q would add Go escaping, not JSON escaping
		}
		lines = append(lines, "}")
		output = strings.Join(lines, "\n") + "\n"
	case "yaml":
		var lines []string
		for _, k := range keys {
			escaped := escapeYAMLValue(secrets[k])
			lines = append(lines, fmt.Sprintf("%s: %s", k, escaped))
		}
		output = strings.Join(lines, "\n") + "\n"
	case "k8s-secret":
		if exportK8sName == "" {
			return fmt.Errorf("--name is required for k8s-secret format")
		}
		lines := []string{
			"apiVersion: v1",
			"kind: Secret",
			"metadata:",
			fmt.Sprintf("  name: %s", exportK8sName),
			fmt.Sprintf("  namespace: %s", exportK8sNs),
			"type: Opaque",
			"data:",
		}
		for _, k := range keys {
			encoded := base64.StdEncoding.EncodeToString([]byte(secrets[k]))
			lines = append(lines, fmt.Sprintf("  %s: %s", k, encoded))
		}
		output = strings.Join(lines, "\n") + "\n"
	default:
		return fmt.Errorf("unknown format: %s (valid: dotenv, json, yaml, k8s-secret)", exportFormat)
	}

	if exportOutput != "" {
		if err := os.WriteFile(exportOutput, []byte(output), 0o600); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Exported %d secrets to %s\n", len(keys), exportOutput)
		return nil
	}

	fmt.Print(output)
	return nil
}
