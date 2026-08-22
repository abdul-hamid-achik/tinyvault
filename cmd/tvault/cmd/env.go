package cmd

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	envFormat      string
	envExport      bool
	envK8sName     string
	envK8sNs       string
	envIdentity    string
	envPulumiStack string
	envGroupFlag   string
	envEnvFlag     string
	envOnly        []string
	envPrefix      string
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
  tvault env --only DATABASE_URL,REDIS_URL --format=dotenv
  tvault env --prefix CHALUPA_ --format=dotenv
  tvault env --format=k8s-secret --name=my-secrets > secret.yaml
  tvault env --format=pulumi-config --stack=prod | sh   # push into Pulumi config
  source <(tvault env)`,
	RunE: runEnv,
}

func init() {
	rootCmd.AddCommand(envCmd)
	envCmd.Flags().StringVarP(&envFormat, "format", "f", "shell", "Output format: shell, dotenv, json, yaml, k8s-secret, pulumi-config")
	envCmd.Flags().BoolVarP(&envExport, "export", "e", true, "Include 'export' prefix (shell format only)")
	envCmd.Flags().StringVar(&envK8sName, "name", "", "Kubernetes Secret name (required for k8s-secret format)")
	envCmd.Flags().StringVar(&envK8sNs, "namespace", "default", "Kubernetes namespace (k8s-secret format)")
	envCmd.Flags().StringVar(&envIdentity, "identity", "", "Decrypt a shared project with this X25519 identity instead of the passphrase")
	envCmd.Flags().StringVar(&envPulumiStack, "stack", "", "Pulumi stack to target (pulumi-config format; optional)")
	envCmd.Flags().StringVar(&envGroupFlag, "group", "", "Resolve secrets through an environment group's inheritance chain")
	envCmd.Flags().StringVar(&envEnvFlag, "env", "", "Environment name within the group (requires --group)")
	envCmd.Flags().StringSliceVar(&envOnly, "only", nil, "Emit only these secret keys (comma-separated allowlist; missing keys fail)")
	envCmd.Flags().StringVar(&envPrefix, "prefix", "", "Emit only secret keys with this prefix")
}

// envSecrets returns the project's decrypted secrets, either via the
// passphrase (default) or, when an identity is explicitly requested (--identity
// or the TVAULT_IDENTITY_KEY environment variable), via a shared X25519
// identity (recipient read — no passphrase, no unlock).
func envSecrets() (map[string]string, error) {
	secrets, _, err := envSecretsSelected(nil, "")
	return secrets, err
}

func runEnv(_ *cobra.Command, _ []string) error {
	secrets, missing, err := envSecretsSelected(envOnly, envPrefix)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("--only key(s) not found: %s", strings.Join(missing, ", "))
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
		return writeJSON(secrets)
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
	case "pulumi-config":
		// Emit `pulumi config set --secret KEY VALUE` lines, shell-quoted so the
		// output is safe to pipe to `sh`. Prefer `tvault run -- pulumi up` when
		// you can — it avoids first copying provider credentials into Pulumi
		// config or the parent shell; this format is for teams that do want them
		// in Pulumi config. The Pulumi program still controls what reaches state.
		stackArg := ""
		if envPulumiStack != "" {
			stackArg = " --stack " + shellArgQuote(envPulumiStack)
		}
		for _, k := range keys {
			fmt.Printf("pulumi config set --secret%s %s %s\n", stackArg, k, shellArgQuote(secrets[k]))
		}
	default:
		return fmt.Errorf("unknown format: %s (valid: shell, dotenv, json, yaml, k8s-secret, pulumi-config)", envFormat)
	}

	return nil
}

// shellArgQuote quotes a value for use as a shell command argument (not an
// assignment RHS). Unlike escapeShellValue, it also guards glob metacharacters
// (* ? [) and other word-splitting/expansion chars, since `pulumi config set
// KEY VALUE` output is meant to be piped to `sh`. It single-quotes anything
// outside a conservative safe set (the shlex.quote convention).
func shellArgQuote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		safe := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("@%+=:,./-_", r)
		if !safe {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
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
