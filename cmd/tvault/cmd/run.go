package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/processenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/redact"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var (
	runEnvFile    string
	runEnvNoVault bool
	runOnly       []string
	runPrefix     string
	runGroup      string
	runEnvName    string
	runStrict     bool
	runIdentity   string
	runRedact     bool
)

var runCmd = &cobra.Command{
	Use:   "run [flags] <command> [args...]",
	Short: "Run a command with secrets as environment variables",
	Long: `Run a command with all project secrets injected as environment variables.

This is useful for running applications that need access to secrets
without exposing them in shell history or scripts.

A .env file can be supplied with --env-file. The file's values are
merged with the vault, with the vault taking precedence. Values
containing ${tvault://project/key} placeholders are resolved against
the vault at run time.

Use "--" to separate the tvault flags from the command's own flags:

  tvault run --env-file .env -- npm start          # npm gets no flags
  tvault run -- docker compose up --build         # compose gets flags
  tvault run python manage.py runserver            # no flag conflict

Inject only a subset of the project's secrets (least privilege) with
--only (an explicit allowlist) and/or --prefix (every key with that
prefix). A key is injected if it matches either selector. Explicit
${tvault://...} references in --env-file still resolve against the full
project, so the filters only narrow the bulk auto-injection.

Examples:
  tvault run -- npm start
  tvault run --env-file .env -- npm start
  tvault run --only DIGITALOCEAN_TOKEN,NUXT_DATABASE_URL -- pulumi up
  tvault run --prefix NUXT_ -- bun run dev`,
	RunE: runRun,
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&runEnvFile, "env-file", "e", "", "Dotenv file to load (vault values are merged on top)")
	runCmd.Flags().BoolVar(&runEnvNoVault, "no-vault", false, "Do not load vault secrets; only use --env-file values")
	runCmd.Flags().StringSliceVar(&runOnly, "only", nil, "Inject only these secret keys (comma-separated allowlist)")
	runCmd.Flags().StringVar(&runPrefix, "prefix", "", "Inject only secret keys with this prefix")
	runCmd.Flags().StringVar(&runGroup, "group", "", "Resolve secrets through an environment group's inheritance chain")
	runCmd.Flags().StringVar(&runEnvName, "env", "", "Environment name within the group (requires --group)")
	runCmd.Flags().BoolVar(&runStrict, "strict", false, "Fail if any --only key is missing instead of warning")
	runCmd.Flags().StringVar(&runIdentity, "identity", "", "Decrypt a shared project with this X25519 identity instead of the passphrase")
	runCmd.Flags().BoolVar(&runRedact, "redact", false, "Replace literal injected secret values in child stdout/stderr with [REDACTED:KEY] (safety net; misses short, split, or transformed values)")
}

func runRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("command is required")
	}

	// Handle -- separator.
	if args[0] == "--" {
		args = args[1:]
		if len(args) == 0 {
			return fmt.Errorf("command is required after --")
		}
	}
	if err := validateGroupEnvFlags(runGroup, runEnvName); err != nil {
		return err
	}
	if runEnvNoVault && (len(runOnly) > 0 || runPrefix != "") {
		return fmt.Errorf("--only/--prefix select vault secrets and cannot be combined with --no-vault")
	}
	if runEnvNoVault && runGroup != "" {
		return fmt.Errorf("--group/--env select vault secrets and cannot be combined with --no-vault")
	}
	identityRequested := runIdentity != "" || strings.TrimSpace(os.Getenv(envIdentityKey)) != ""
	if runEnvNoVault && identityRequested {
		return fmt.Errorf("--identity selects vault secrets and cannot be combined with --no-vault")
	}

	var vaultSecrets map[string]string
	var project string
	var missing []string
	var loadSecret func(string, string) (string, error)

	// bbolt holds an exclusive process-wide lock, so the vault must be closed
	// before the child starts: a long-lived child (an MCP server, a dev server)
	// would otherwise block every other tvault invocation on the machine for as
	// long as it runs. releaseVault is called explicitly once the environment is
	// fully built; the defer is only a safety net for the error paths above it.
	var openedVault *vault.Vault
	releaseVault := func() {
		if openedVault != nil {
			_ = openedVault.Close()
			openedVault = nil
		}
	}
	defer releaseVault()

	if !runEnvNoVault {
		selectorsPresent := len(runOnly) > 0 || runPrefix != ""
		switch {
		case runGroup != "" && runEnvName != "":
			// Resolution through environment group inheritance.
			var v *vault.Vault
			var idSource string
			var idErr error
			var id *crypto.Identity
			if identityRequested {
				id, idSource, idErr = resolveIdentity(runIdentity)
				if idErr != nil {
					return idErr
				}
				if id == nil {
					return fmt.Errorf("no identity available: pass --identity <name> or set %s", envIdentityKey)
				}
				v, idErr = vault.Open(getVaultDir())
				if idErr != nil {
					return wrapVaultOpenErr(getVaultDir(), idErr)
				}
				warnEnvKeyUsed(os.Stderr, idSource, "run")
			} else {
				v, idErr = openAndUnlockVault()
				if idErr != nil {
					return idErr
				}
			}
			openedVault = v
			var resolveErr error
			switch {
			case identityRequested && selectorsPresent:
				vaultSecrets, missing, project, resolveErr = resolveSelectedWithInheritanceIdentity(v, id, runGroup, runEnvName, runOnly, runPrefix)
			case identityRequested:
				vaultSecrets, project, resolveErr = resolveAllWithInheritanceIdentity(v, id, runGroup, runEnvName)
			case selectorsPresent:
				vaultSecrets, missing, project, resolveErr = resolveSelectedWithInheritance(v, runGroup, runEnvName, runOnly, runPrefix)
			default:
				vaultSecrets, project, resolveErr = resolveAllWithInheritance(v, runGroup, runEnvName)
			}
			if resolveErr != nil {
				return fmt.Errorf("failed to resolve secrets: %w", resolveErr)
			}
			if identityRequested {
				recordAudit(v, "secret.read", "environment_group", runGroup, map[string]any{
					"via": "identity", "source": idSource, "environment": runEnvName, "selected": selectorsPresent,
				})
			}
			loadSecret = func(referenceProject, key string) (string, error) {
				if referenceProject == project {
					var selected map[string]string
					var absent []string
					var selectErr error
					if identityRequested {
						selected, absent, _, selectErr = resolveSelectedWithInheritanceIdentity(v, id, runGroup, runEnvName, []string{key}, "")
					} else {
						selected, absent, _, selectErr = resolveSelectedWithInheritance(v, runGroup, runEnvName, []string{key}, "")
					}
					if selectErr != nil {
						return "", selectErr
					}
					if len(absent) > 0 {
						return "", fmt.Errorf("secret %q not found in project %q", key, referenceProject)
					}
					return selected[key], nil
				}
				if identityRequested {
					selected, absent, selectErr := v.GetSelectedSecretsWithIdentity(referenceProject, id, []string{key}, "")
					if selectErr != nil {
						return "", fmt.Errorf("read project %q with identity: %w", referenceProject, selectErr)
					}
					if len(absent) > 0 {
						return "", fmt.Errorf("secret %q not found in project %q", key, referenceProject)
					}
					return selected[key], nil
				}
				return loadRunProjectSecret(referenceProject, key)
			}

		case identityRequested:
			id, source, err := resolveIdentity(runIdentity)
			if err != nil {
				return err
			}
			if id == nil {
				return fmt.Errorf("no identity available: pass --identity <name> or set %s", envIdentityKey)
			}
			v, err := vault.Open(getVaultDir())
			if err != nil {
				return wrapVaultOpenErr(getVaultDir(), err)
			}
			openedVault = v
			warnEnvKeyUsed(os.Stderr, source, "run")
			project = resolveProject(v, projectName)
			if selectorsPresent {
				vaultSecrets, missing, err = v.GetSelectedSecretsWithIdentity(project, id, runOnly, runPrefix)
			} else {
				vaultSecrets, err = v.GetAllSecretsWithIdentity(project, id)
			}
			if err != nil {
				return fmt.Errorf("read project %q with identity: %w", project, err)
			}
			recordAudit(v, "secret.read", "project", project, map[string]any{"via": "identity", "source": source, "selected": selectorsPresent})
			loadSecret = func(referenceProject, key string) (string, error) {
				selected, absent, selectErr := v.GetSelectedSecretsWithIdentity(referenceProject, id, []string{key}, "")
				if selectErr != nil {
					return "", fmt.Errorf("read project %q with identity: %w", referenceProject, selectErr)
				}
				if len(absent) > 0 {
					return "", fmt.Errorf("secret %q not found in project %q", key, referenceProject)
				}
				return selected[key], nil
			}

		case selectorsPresent:
			if secrets, absent, resolved, ok := agentSelectedSecrets(projectName, runOnly, runPrefix); ok {
				vaultSecrets, missing, project = secrets, absent, resolved
			} else {
				v, err := openAndUnlockVault()
				if err != nil {
					return err
				}
				project = resolveProject(v, projectName)
				vaultSecrets, missing, err = v.GetSelectedSecrets(project, runOnly, runPrefix)
				v.Close()
				if err != nil {
					return fmt.Errorf("failed to get selected secrets: %w", err)
				}
			}
			loadSecret = loadRunProjectSecret

		default:
			if secrets, resolved, ok := agentAllSecrets(projectName); ok {
				// Fast path: a running agent serves the project's secrets prompt-free.
				vaultSecrets, project = secrets, resolved
			} else {
				v, err := openAndUnlockVault()
				if err != nil {
					return err
				}
				project = resolveProject(v, projectName)
				vaultSecrets, err = v.GetAllSecrets(project)
				v.Close()
				if err != nil {
					return fmt.Errorf("failed to get secrets: %w", err)
				}
			}
			loadSecret = loadRunProjectSecret
		}
	}

	if len(missing) > 0 {
		if runStrict {
			return fmt.Errorf("--only key(s) not found in project %q: %s", project, strings.Join(missing, ", "))
		}
		fmt.Fprintf(os.Stderr, "warning: --only key(s) not found in project %q: %s\n", project, strings.Join(missing, ", "))
	}

	// Explicit references are resolved one key at a time. This keeps bulk
	// selection least-privilege while preserving env-file interpolation.
	resolver := newRunRefResolver(project, vaultSecrets, loadSecret)

	merged := make(map[string]string, len(vaultSecrets))
	for k, v := range vaultSecrets {
		merged[k] = v
	}

	if runEnvFile != "" {
		parsed, err := dotenv.ParseFile(runEnvFile)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", runEnvFile, err)
		}
		for _, e := range parsed.Entries {
			val := e.Value
			if dotenv.HasRef(val) {
				resolved, err := dotenv.Resolve(val, resolver)
				if err != nil {
					return fmt.Errorf("interpolate %s: %w", e.Key, err)
				}
				val = resolved
			}
			// Vault wins on conflict.
			if _, exists := merged[e.Key]; !exists {
				merged[e.Key] = val
			}
		}
	}

	// Build environment.
	env := processenv.Sanitize(os.Environ())
	for key, value := range merged {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	env = processenv.Sanitize(env)

	// Every secret is now materialized in env; drop bbolt's exclusive lock so
	// the child (which may run indefinitely) never blocks other tvault processes.
	releaseVault()

	// Find the executable.
	executable, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}

	// Create the command.
	execCmd := exec.CommandContext(cmd.Context(), executable, args[1:]...)
	execCmd.Env = env
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	if runRedact {
		execCmd.Stdout = redact.Writer(os.Stdout, merged)
		execCmd.Stderr = redact.Writer(os.Stderr, merged)
	}

	// Handle signals.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the command.
	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Forward signals to the child process.
	go func() {
		sig := <-sigChan
		if execCmd.Process != nil {
			_ = execCmd.Process.Signal(sig)
		}
	}()

	// Wait for the command to finish.
	if err := execCmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

func loadRunProjectSecret(project, key string) (string, error) {
	if value, ok := agentGetSecret(project, key); ok {
		return value, nil
	}
	v, err := openAndUnlockVault()
	if err != nil {
		return "", err
	}
	defer v.Close()
	value, err := v.GetSecret(project, key)
	if err != nil {
		return "", fmt.Errorf("get secret %q for project %q: %w", key, project, err)
	}
	return value, nil
}

func newRunRefResolver(
	currentProject string,
	currentSecrets map[string]string,
	loadSecret func(string, string) (string, error),
) func(dotenv.Ref) (string, error) {
	cache := map[string]map[string]string{}
	if currentProject != "" && currentSecrets != nil {
		cache[currentProject] = currentSecrets
	}
	return func(ref dotenv.Ref) (string, error) {
		if currentSecrets == nil {
			return "", fmt.Errorf("vault not loaded (use --no-vault=false or remove ${tvault://...} references)")
		}
		project := ref.Project
		if project == "" || project == "current" {
			if currentProject == "" {
				return "", fmt.Errorf("no current project; use tvault://PROJECT/KEY syntax")
			}
			project = currentProject
		}
		secrets := cache[project]
		value, ok := secrets[ref.Key]
		if !ok {
			if loadSecret == nil {
				return "", fmt.Errorf("vault not loaded (use --no-vault=false or remove ${tvault://...} references)")
			}
			var err error
			value, err = loadSecret(project, ref.Key)
			if err != nil {
				return "", fmt.Errorf("load secret %q from project %q: %w", ref.Key, project, err)
			}
			if secrets == nil {
				secrets = make(map[string]string)
				cache[project] = secrets
			}
			secrets[ref.Key] = value
		}
		return value, nil
	}
}

// selectSecrets returns the subset of all whose keys match the --only allowlist
// or the --prefix (union semantics: a key is kept if it matches either). It also
// reports any --only keys that are absent from the project, so a typo surfaces
// as a warning rather than silently injecting nothing.
func selectSecrets(all map[string]string, only []string, prefix string) (selected map[string]string, missingOnly []string) {
	onlySet := make(map[string]bool, len(only))
	for _, k := range only {
		onlySet[k] = true
	}

	selected = make(map[string]string)
	for k, v := range all {
		if onlySet[k] || (prefix != "" && strings.HasPrefix(k, prefix)) {
			selected[k] = v
		}
	}

	for _, k := range only {
		if _, ok := all[k]; !ok {
			missingOnly = append(missingOnly, k)
		}
	}
	sort.Strings(missingOnly)
	return selected, missingOnly
}
