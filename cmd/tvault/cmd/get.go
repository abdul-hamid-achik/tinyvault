package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

var (
	getFromFile   string
	getVersion    int
	getGroup      string
	getEnv        string
	getShowSource bool
)

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a secret value",
	Long: `Get the value of a secret by key.

The decrypted value is printed to stdout. Messages go to stderr,
making this command pipe-friendly.

When --from is used, the value is read from a dotenv file instead of
the vault. The file does not need to be unlocked; the value is read
verbatim (no interpolation). Use tvault run for ${tvault://...} resolution.

Pass --version N to print a specific historical version (see tvault history).

When --group and --env are used together, the value is resolved through
the environment group's inheritance chain: the child environment's local
value is returned if present, otherwise the base environment's value.

Examples:
  tvault get DATABASE_URL
  tvault get API_KEY --json
  tvault get DATABASE_URL --from .env
  tvault get API_KEY --version 2
  tvault get STRIPE_KEY --group liftclub --env preview --show-source
  DB_URL=$(tvault get DATABASE_URL)`,
	Aliases: []string{"g"},
	Args:    cobra.ExactArgs(1),
	RunE:    runGet,
}

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().StringVarP(&getFromFile, "from", "", "", "Read value from a dotenv file instead of the vault")
	getCmd.Flags().IntVar(&getVersion, "version", 0, "Print a specific historical version (default: current)")
	getCmd.Flags().StringVar(&getGroup, "group", "", "Resolve through an environment group's inheritance chain")
	getCmd.Flags().StringVar(&getEnv, "env", "", "Environment name within the group (requires --group)")
	getCmd.Flags().BoolVar(&getShowSource, "show-source", false, "Show which environment a resolved value came from (with --group)")
}

func runGet(_ *cobra.Command, args []string) error {
	if err := validateGetFlags(); err != nil {
		return err
	}

	key := args[0]

	if getFromFile != "" {
		value, err := getFromDotenv(getFromFile, key)
		if err != nil {
			return err
		}
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]string{"key": key, "value": value, "source": getFromFile})
		}
		fmt.Print(value)
		return nil
	}

	// Fast path: a running agent serves direct current-version reads with no
	// prompt and no Argon2id. Historical versions (--version) and environment
	// group resolution always go direct because the agent protocol does not
	// carry group/environment context.
	if getVersion == 0 && getGroup == "" && getEnv == "" {
		if value, ok := agentGetSecret(projectName, key); ok {
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"key": key, "value": value})
			}
			fmt.Print(value)
			return nil
		}
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	// Resolution through environment group inheritance.
	if getGroup != "" && getEnv != "" {
		value, source, rErr := v.ResolveKey(getGroup, getEnv, key)
		if rErr != nil {
			return fmt.Errorf("failed to resolve secret: %w", rErr)
		}
		recordAudit(v, "secret.read", "secret", key, map[string]any{"group": getGroup, "env": getEnv, "source": source})
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			out := map[string]any{"key": key, "value": value, "source": source}
			return enc.Encode(out)
		}
		if getShowSource {
			fmt.Fprintf(os.Stderr, "# inherited from %s\n", source)
		}
		fmt.Print(value)
		return nil
	}

	project := resolveProject(v, projectName)

	var value string
	if getVersion > 0 {
		value, err = v.GetSecretVersionValue(project, key, getVersion)
		if err != nil {
			return fmt.Errorf("failed to get secret version %d: %w", getVersion, err)
		}
		recordAudit(v, "secret.read", "secret", key, map[string]any{"project": project, "version": getVersion, "source": "version"})
	} else {
		value, err = v.GetSecret(project, key)
		if err != nil {
			return fmt.Errorf("failed to get secret: %w", err)
		}
		recordAudit(v, "secret.read", "secret", key, map[string]any{"project": project})
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		out := map[string]any{"key": key, "value": value}
		if getVersion > 0 {
			out["version"] = getVersion
		}
		return enc.Encode(out)
	}

	fmt.Print(value)
	return nil
}

// validateGetFlags rejects ambiguous source selection before runGet reads a
// dotenv file, contacts the agent, or opens the vault. A get reads from exactly
// one source: the current project, a dotenv file, a historical version, or an
// environment group.
func validateGetFlags() error {
	hasGroup := getGroup != ""

	if getVersion < 0 {
		return fmt.Errorf("--version cannot be negative")
	}
	if err := validateGroupEnvFlags(getGroup, getEnv); err != nil {
		return err
	}
	if getFromFile != "" && getVersion > 0 {
		return fmt.Errorf("--from and --version are mutually exclusive")
	}
	if getFromFile != "" && hasGroup {
		return fmt.Errorf("--from and --group/--env are mutually exclusive")
	}
	if getFromFile != "" && getShowSource {
		return fmt.Errorf("--from and --show-source are mutually exclusive")
	}
	if getVersion > 0 && hasGroup {
		return fmt.Errorf("--version is not supported with --group/--env")
	}
	if getVersion > 0 && getShowSource {
		return fmt.Errorf("--version and --show-source are mutually exclusive")
	}
	if getShowSource && !hasGroup {
		return fmt.Errorf("--show-source requires --group and --env")
	}

	return nil
}

// getFromDotenv reads a single key from a dotenv file without touching
// the vault. The file name still goes through the safety allowlist so
// that a malicious path like `~/.bashrc` cannot be smuggled in.
func getFromDotenv(path, key string) (string, error) {
	parsed, err := dotenv.ParseFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", path, err)
	}
	for _, e := range parsed.Entries {
		if e.Key == key {
			return e.Value, nil
		}
	}
	return "", fmt.Errorf("key %q not found in %s", key, path)
}
