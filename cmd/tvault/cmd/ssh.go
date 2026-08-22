package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	sshOnly     []string
	sshPrefix   string
	sshIdentity string
	sshGroup    string
	sshEnvName  string
	sshStrict   bool
	sshArgs     []string
)

var sshCmd = &cobra.Command{
	Use:   "ssh <destination> -- <command> [args...]",
	Short: "Run a remote command with vault secrets in its environment",
	Long: `Run a command on a remote host with the current project's secrets
injected into that process's environment.

Secrets travel over the SSH channel as a short POSIX script on stdin.
They are never written to a remote file and never appear on the ssh
command line (so they do not show up in ps). The remote command runs
via 'sh -s'; the host needs a POSIX sh.

TinyVault flags stay before the destination. Extra ssh client flags
go in repeatable --ssh-arg values. Everything after '--' is the
remote command.

Examples:
  tvault ssh deploy@prod -- systemctl restart api
  tvault ssh --only DATABASE_URL deploy@prod -- ./migrate
  tvault ssh --ssh-arg=-p --ssh-arg=2222 deploy@prod -- hostname
  tvault ssh --identity ci deploy@prod -- docker compose up`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSSH,
}

func init() {
	rootCmd.AddCommand(sshCmd)
	sshCmd.Flags().StringSliceVar(&sshOnly, "only", nil, "Inject only these secret keys (comma-separated allowlist)")
	sshCmd.Flags().StringVar(&sshPrefix, "prefix", "", "Inject only secret keys with this prefix")
	sshCmd.Flags().StringVar(&sshIdentity, "identity", "", "Decrypt a shared project with this X25519 identity instead of the passphrase")
	sshCmd.Flags().StringVar(&sshGroup, "group", "", "Resolve secrets through an environment group's inheritance chain")
	sshCmd.Flags().StringVar(&sshEnvName, "env", "", "Environment name within the group (requires --group)")
	sshCmd.Flags().BoolVar(&sshStrict, "strict", false, "Fail if any --only key is missing instead of warning")
	sshCmd.Flags().StringArrayVar(&sshArgs, "ssh-arg", nil, "Extra argument passed to the ssh client before the destination (repeatable)")
}

func runSSH(c *cobra.Command, args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		return fmt.Errorf("destination and command are required (tvault ssh <destination> -- <command>)")
	}
	dest := args[0]
	remote := args[1:]

	secrets, missing, err := loadSelectedSecrets(secretSelectOpts{
		identity: sshIdentity,
		group:    sshGroup,
		envName:  sshEnvName,
		only:     sshOnly,
		prefix:   sshPrefix,
		via:      "ssh",
	})
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		msg := fmt.Sprintf("--only key(s) not found: %s", strings.Join(missing, ", "))
		if sshStrict {
			return fmt.Errorf("%s", msg)
		}
		fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
	}

	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}

	sshArgv := make([]string, 0, len(sshArgs)+4+len(remote))
	sshArgv = append(sshArgv, sshArgs...)
	sshArgv = append(sshArgv, dest, "sh", "-s", "--")
	sshArgv = append(sshArgv, remote...)

	ctx := context.Background()
	if c != nil {
		ctx = c.Context()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	execCmd := exec.CommandContext(ctx, sshPath, sshArgv...)
	execCmd.Stdin = strings.NewReader(buildSSHInjectScript(secrets))
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start ssh: %w", err)
	}
	go func() {
		sig := <-sigChan
		if execCmd.Process != nil {
			_ = execCmd.Process.Signal(sig)
		}
	}()

	if err := execCmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("ssh failed: %w", err)
	}
	return nil
}

// buildSSHInjectScript emits a POSIX script that exports secrets then
// execs the command passed after `sh -s --`. Values are shell-quoted;
// keys are validated env-var names. The script is the only place
// values appear — not the ssh argv.
func buildSSHInjectScript(secrets map[string]string) string {
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("set -e\n")
	for _, k := range keys {
		b.WriteString("export ")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(escapeShellValue(secrets[k]))
		b.WriteString("\n")
	}
	b.WriteString("exec \"$@\"\n")
	return b.String()
}
