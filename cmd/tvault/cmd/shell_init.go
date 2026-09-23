package cmd

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var (
	shellInitOnly        []string
	shellInitPrefix      string
	shellInitAllowUnlock bool
	shellInitQuiet       bool
)

var shellInitCmd = &cobra.Command{
	Use:   "shell-init <bash|zsh|fish> --project <name>",
	Short: "Print export lines that load a project into a login shell, never prompting",
	Long: `Print the secrets of one project as shell assignments, for eval at shell
startup (~/.zshrc, ~/.bashrc, config.fish).

Unlike 'tvault env', shell-init is built to run unattended while a shell
starts:

  - It never prompts. Values come from a running 'tvault agent'. With
    --allow-unlock it may also unlock directly, but only from a
    non-interactive source (TVAULT_PASSPHRASE, a passphrase command, or a
    passphrase file) — never a TTY prompt.
  - When no source is available it prints nothing on stdout, one notice on
    stderr (silence it with --quiet), and exits 0, so a locked vault never
    blocks or breaks shell startup.
  - --project is required: a login shell must not load whichever project
    'tvault use' last selected.
  - Values are quoted so eval can never execute part of one, and keys that
    are not valid shell identifiers are skipped with a warning.

Every process started from that shell inherits these variables. Prefer
'tvault run -- <cmd>' for secrets only one program needs, and keep the
startup project small (--only / --prefix).

Examples:
  eval "$(tvault shell-init zsh --project personal)"          # ~/.zshrc
  eval "$(tvault shell-init bash -p personal --only GITHUB_TOKEN,OPENAI_API_KEY)"
  tvault shell-init fish --project personal | source           # config.fish
  eval "$(tvault shell-init zsh -p personal --allow-unlock --quiet)"`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"bash", "zsh", "fish"},
	RunE:      runShellInit,
}

func init() {
	rootCmd.AddCommand(shellInitCmd)
	shellInitCmd.Flags().StringSliceVar(&shellInitOnly, "only", nil, "Load only these keys (comma-separated)")
	shellInitCmd.Flags().StringVar(&shellInitPrefix, "prefix", "", "Load only keys with this prefix")
	shellInitCmd.Flags().BoolVar(&shellInitAllowUnlock, "allow-unlock", false,
		"When no agent is reachable, unlock from a non-interactive source (env, passphrase command, passphrase file)")
	shellInitCmd.Flags().BoolVarP(&shellInitQuiet, "quiet", "q", false, "Do not print a notice when the vault is locked")
}

// shellIdentifier matches names every supported shell accepts as a variable.
var shellIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func runShellInit(_ *cobra.Command, args []string) error {
	shell := strings.ToLower(args[0])
	switch shell {
	case "bash", "zsh", "fish":
	default:
		return fmt.Errorf("unknown shell %q (supported: bash, fish, zsh)", args[0])
	}
	if strings.TrimSpace(projectName) == "" {
		return fmt.Errorf("shell-init needs --project: a login shell must load a named project, not the current one")
	}

	secrets, missing, reason, err := shellInitSecrets()
	if err != nil {
		return err
	}
	if secrets == nil {
		if !shellInitQuiet {
			fmt.Fprintf(os.Stderr, "tvault: %s; project %q not loaded into this shell\n", reason, projectName)
		}
		return nil
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "tvault: --only key(s) not found in %q: %s\n", projectName, strings.Join(missing, ", "))
	}
	writeShellAssignments(os.Stdout, os.Stderr, shell, secrets)
	return nil
}

// shellInitSecrets reads the project through the agent, or — with
// --allow-unlock — through a non-interactive direct unlock. A nil map with a
// reason means "nothing available, stay quiet"; an error means the request
// itself is wrong (e.g. the project does not exist) and should be surfaced.
func shellInitSecrets() (secrets map[string]string, missing []string, reason string, err error) {
	selected := len(shellInitOnly) > 0 || shellInitPrefix != ""

	if c, ok := dialAgent(); ok {
		if selected {
			secrets, missing, _, err = c.GetSelected(projectName, shellInitOnly, shellInitPrefix)
		} else {
			secrets, _, err = c.GetAll(projectName)
		}
		if err == nil {
			return nonNil(secrets), missing, "", nil
		}
		if !shellInitAllowUnlock {
			return nil, nil, "", fmt.Errorf("read %q through the agent: %w", projectName, err)
		}
	}
	if !shellInitAllowUnlock {
		return nil, nil, "no tvault agent is running (start one, or pass --allow-unlock)", nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, "", fmt.Errorf("read %s: %w", configPath(), err)
	}
	pass, err := nonInteractivePassphrase(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	if pass == "" {
		return nil, nil, "the vault is locked and no non-interactive passphrase source is configured", nil
	}
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return nil, nil, "", wrapVaultOpenErr(dir, err)
	}
	defer v.Close()
	if uerr := v.Unlock(pass); uerr != nil {
		return nil, nil, "", uerr
	}
	if selected {
		secrets, missing, err = v.GetSelectedSecrets(projectName, shellInitOnly, shellInitPrefix)
	} else {
		secrets, err = v.GetAllSecrets(projectName)
	}
	if err != nil {
		return nil, nil, "", fmt.Errorf("read %q: %w", projectName, err)
	}
	return nonNil(secrets), missing, "", nil
}

// nonNil keeps an empty project distinguishable from "nothing available".
func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// writeShellAssignments prints one assignment per valid key, sorted. Keys
// that are not shell identifiers are reported on warn by name only: emitting
// them would let a key such as "A;id" inject a command into the eval.
func writeShellAssignments(out, warn io.Writer, shell string, secrets map[string]string) {
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !shellIdentifier.MatchString(k) {
			fmt.Fprintf(warn, "tvault: skipping %q: not a valid shell variable name\n", k)
			continue
		}
		if shell == "fish" {
			fmt.Fprintf(out, "set -gx %s %s\n", k, fishQuote(secrets[k]))
		} else {
			fmt.Fprintf(out, "export %s=%s\n", k, escapeShellValue(secrets[k]))
		}
	}
}

// fishQuote single-quotes s for fish, where only \ and ' are special inside
// single quotes.
func fishQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}
