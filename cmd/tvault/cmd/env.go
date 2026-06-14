package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var (
	envFormat   string
	envExport   bool
	envK8sName  string
	envK8sNs    string
	envIdentity string
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
	envCmd.Flags().StringVar(&envIdentity, "identity", "", "Decrypt a shared project with this X25519 identity instead of the passphrase")
}

// envSecrets returns the project's decrypted secrets, either via the
// passphrase (default) or, when an identity is explicitly requested (--identity
// or the TVAULT_IDENTITY_KEY environment variable), via a shared X25519
// identity (recipient read — no passphrase, no unlock).
func envSecrets() (map[string]string, error) {
	// The recipient path is opt-in only: a stray ~/.tvault/identities/default.key
	// must not silently divert a plain `tvault env` away from the passphrase.
	if envIdentity != "" || strings.TrimSpace(os.Getenv(envIdentityKey)) != "" {
		id, source, err := resolveIdentity(envIdentity)
		if err != nil {
			return nil, err
		}
		if id == nil {
			return nil, fmt.Errorf("no identity available: pass --identity <name> or set %s", envIdentityKey)
		}
		dir := getVaultDir()
		v, err := vault.Open(dir)
		if err != nil {
			return nil, fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", dir, err)
		}
		defer v.Close()
		warnEnvKeyUsed(os.Stderr, source, "env")
		project := resolveProject(v, projectName)
		secrets, err := v.GetAllSecretsWithIdentity(project, id)
		if err != nil {
			return nil, fmt.Errorf("read project %q with identity: %w", project, err)
		}
		recordAudit(v, "secret.read", "project", project, map[string]any{"via": "identity", "source": source})
		return secrets, nil
	}

	// Fast path: a running agent serves the project's secrets prompt-free.
	if secrets, _, ok := agentAllSecrets(projectName); ok {
		return secrets, nil
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return nil, err
	}
	defer v.Close()
	project := resolveProject(v, projectName)
	secrets, err := v.GetAllSecrets(project)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}
	return secrets, nil
}

func runEnv(_ *cobra.Command, _ []string) error {
	secrets, err := envSecrets()
	if err != nil {
		return err
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

// escapeJSONValue returns s escaped for embedding between double quotes in
// JSON. It uses encoding/json so ALL control bytes (\r, \b, \f, NUL, …)
// are escaped — the previous hand-rolled version only handled \ " \n \t,
// which produced invalid JSON for values containing other control bytes.
// HTML escaping is disabled so values like connection strings keep their
// literal & < > characters.
func escapeJSONValue(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	//nolint:errcheck // encoding a string into a bytes.Buffer cannot fail
	enc.Encode(s)
	out := strings.TrimRight(buf.String(), "\n")
	if len(out) >= 2 { // strip the surrounding quotes Encode adds
		return out[1 : len(out)-1]
	}
	return out
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
