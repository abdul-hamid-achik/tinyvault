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

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

var (
	runEnvFile    string
	runEnvNoVault bool
	runOnly       []string
	runPrefix     string
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
}

func runRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("command is required")
	}

	if runEnvNoVault && (len(runOnly) > 0 || runPrefix != "") {
		return fmt.Errorf("--only/--prefix select vault secrets and cannot be combined with --no-vault")
	}

	// Handle -- separator.
	if args[0] == "--" {
		args = args[1:]
		if len(args) == 0 {
			return fmt.Errorf("command is required after --")
		}
	}

	var vaultSecrets map[string]string
	var project string
	if !runEnvNoVault {
		// Fast path: a running agent serves the project's secrets prompt-free.
		if secrets, resolved, ok := agentAllSecrets(projectName); ok {
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
	}

	// Resolve any tvault:// references in env file values against the
	// vault so a templated .env can be committed safely.
	resolver := func(ref dotenv.Ref) (string, error) {
		if vaultSecrets == nil {
			return "", fmt.Errorf("vault not loaded (use --no-vault=false or remove ${tvault://...} references)")
		}
		proj := ref.Project
		if proj == "" || proj == "current" {
			if project == "" {
				return "", fmt.Errorf("no current project; use tvault://PROJECT/KEY syntax")
			}
			proj = project
		}
		val, ok := vaultSecrets[ref.Key]
		if !ok {
			return "", fmt.Errorf("secret %q not found in project %q", ref.Key, proj)
		}
		return val, nil
	}

	// --only/--prefix narrow the bulk auto-injection (least privilege). The
	// full set stays available to the resolver above, so explicit
	// ${tvault://...} references in an env file still work.
	injected := vaultSecrets
	if len(runOnly) > 0 || runPrefix != "" {
		var missing []string
		injected, missing = selectSecrets(vaultSecrets, runOnly, runPrefix)
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "warning: --only key(s) not found in project %q: %s\n",
				project, strings.Join(missing, ", "))
		}
	}

	merged := make(map[string]string, len(injected))
	for k, v := range injected {
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
	env := os.Environ()
	for key, value := range merged {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

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
