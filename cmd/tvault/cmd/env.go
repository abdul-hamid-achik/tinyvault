package cmd

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	envFormat  string
	envExport  bool
	envK8sName string
	envK8sNs   string
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Export secrets as environment variables",
	Long: `Export all secrets as environment variables in various formats.

The output can be used with shell eval, saved to an .env file,
or exported as YAML or Kubernetes Secret manifests.

Examples:
  eval $(tvault env)
  tvault env --format=dotenv > .env
  tvault env --format=yaml > secrets.yaml
  tvault env --format=k8s-secret --name=my-secrets > secret.yaml
  source <(tvault env)`,
	RunE: runEnv,
}

func init() {
	rootCmd.AddCommand(envCmd)
	envCmd.Flags().StringVarP(&envFormat, "format", "f", "shell", "Output format: shell, dotenv, json, yaml, k8s-secret")
	envCmd.Flags().BoolVarP(&envExport, "export", "e", true, "Include 'export' prefix (shell format only)")
	envCmd.Flags().StringVar(&envK8sName, "name", "", "Kubernetes Secret name (required for k8s-secret format)")
	envCmd.Flags().StringVar(&envK8sNs, "namespace", "default", "Kubernetes namespace (k8s-secret format)")
}

func runEnv(_ *cobra.Command, _ []string) error {
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
		return nil
	}

	// Sort keys for consistent output.
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
	case "yaml":
		for _, k := range keys {
			v := secrets[k]
			escaped := escapeYAMLValue(v)
			fmt.Printf("%s: %s\n", k, escaped)
		}
	case "k8s-secret":
		if envK8sName == "" {
			return fmt.Errorf("--name is required for k8s-secret format")
		}
		fmt.Println("apiVersion: v1")
		fmt.Println("kind: Secret")
		fmt.Println("metadata:")
		fmt.Printf("  name: %s\n", envK8sName)
		fmt.Printf("  namespace: %s\n", envK8sNs)
		fmt.Println("type: Opaque")
		fmt.Println("data:")
		for _, k := range keys {
			v := secrets[k]
			encoded := base64.StdEncoding.EncodeToString([]byte(v))
			fmt.Printf("  %s: %s\n", k, encoded)
		}
	default:
		return fmt.Errorf("unknown format: %s (valid: shell, dotenv, json, yaml, k8s-secret)", envFormat)
	}

	return nil
}

func escapeShellValue(s string) string {
	if !strings.ContainsAny(s, "'\"\\$`\n\t ") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func escapeDotenvValue(s string) string {
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

func escapeYAMLValue(s string) string {
	needsQuoting := strings.ContainsAny(s, ":#{}[]!|>&*?-@`'\"\\\n\t") ||
		strings.HasPrefix(s, " ") ||
		strings.HasSuffix(s, " ") ||
		s == "" ||
		s == "true" || s == "false" ||
		s == "yes" || s == "no" ||
		s == "null" || s == "~"

	if !needsQuoting {
		if _, err := fmt.Sscanf(s, "%f", new(float64)); err == nil {
			needsQuoting = true
		}
	}

	if !needsQuoting {
		return s
	}

	escaped := strings.ReplaceAll(s, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	escaped = strings.ReplaceAll(escaped, "\n", "\\n")
	escaped = strings.ReplaceAll(escaped, "\t", "\\t")
	return "\"" + escaped + "\""
}
