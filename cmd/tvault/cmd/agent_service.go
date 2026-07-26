package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/logging"
	"github.com/abdul-hamid-achik/tinyvault/internal/service"
)

var (
	agentInstallDryRun bool
	agentInstallNoLoad bool
)

var agentInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the agent as a per-user service (launchd on macOS, systemd on Linux)",
	Long: `Install ` + "`tvault agent start`" + ` as a per-user background service: a
launchd LaunchAgent on macOS, a systemd user unit on Linux.

The agent never daemonizes itself (forking a live Go runtime is unsafe), so the
service manager owns the backgrounding — launchd RunAtLoad, systemd Type=simple.

Because a service has no terminal, the agent needs a non-interactive way to
unlock. Point it at an env-style file holding TVAULT_PASSPHRASE:

  tvault agent install --passphrase-file ~/.config/secrets/env

or set ` + "`agent.passphrase_file`" + ` in ~/.tvault/config.yaml. The generated
definition records only the PATH to that file, never the passphrase — a launchd
plist is world-readable by default and ends up in backups. The agent reads the
file itself and refuses one that is readable by group or others.

The service is restarted on failure but NOT after a clean exit, so the agent's
idle auto-lock is respected instead of being immediately undone. After an idle
lock the next read falls back to a direct unlock, which still needs no prompt
when a passphrase file is configured.

Review the definition before writing it with --dry-run.

Examples:
  tvault agent install --dry-run
  tvault agent install --passphrase-file ~/.config/secrets/env
  tvault agent install --idle 0 --log-level debug
  tvault agent uninstall`,
	RunE: runAgentInstall,
}

var agentUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the agent's service definition",
	RunE:  runAgentUninstall,
}

var agentRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the installed agent service (picks up an upgraded binary)",
	Long: `Reload the agent service so it re-executes the tvault binary.

Run this after upgrading tvault: the running agent is the old binary until it is
restarted, since a service manager keeps the process it already started.`,
	RunE: runAgentRestart,
}

var agentLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show where the agent logs live, or clear them with --clear",
	RunE:  runAgentLogs,
}

var agentLogsClear bool

func init() {
	agentCmd.AddCommand(agentInstallCmd, agentUninstallCmd, agentRestartCmd, agentLogsCmd)

	agentInstallCmd.Flags().BoolVar(&agentInstallDryRun, "dry-run", false,
		"Print the service definition and its destination without writing anything")
	agentInstallCmd.Flags().BoolVar(&agentInstallNoLoad, "no-load", false,
		"Write the definition but do not register it with the service manager")
	agentInstallCmd.Flags().StringVar(&agentPassphraseFileFlag, "passphrase-file", "",
		"Env-style file holding TVAULT_PASSPHRASE, so the service can unlock without a TTY")
	agentInstallCmd.Flags().DurationVar(&agentIdle, "idle", defaultAgentIdle,
		"Auto-lock after this idle duration (0 = never)")
	agentInstallCmd.Flags().StringVar(&agentLogDirFlag, "log-dir", "",
		"Directory for agent logs (default $XDG_STATE_HOME/tvault)")
	agentInstallCmd.Flags().StringVar(&agentLogLevelFlag, "log-level", "",
		"Agent log level: debug, info, warn or error (default info)")

	agentLogsCmd.Flags().BoolVar(&agentLogsClear, "clear", false,
		"Delete the agent log and its rotated generation")
	agentLogsCmd.Flags().StringVar(&agentLogDirFlag, "log-dir", "",
		"Directory for agent logs (default $XDG_STATE_HOME/tvault)")
}

var agentPassphraseFileFlag string

// serviceConfig builds the service definition's inputs from flags, environment
// and config. Paths are made absolute because a service manager starts the
// process with an unspecified working directory.
func serviceConfig(cfg Config) (service.Config, error) {
	exe, err := os.Executable()
	if err != nil {
		return service.Config{}, fmt.Errorf("locate the tvault binary: %w", err)
	}
	// Record the path as invoked, symlinks intact. Resolving them is actively
	// harmful for a package manager: /opt/homebrew/bin/tvault is a stable
	// symlink, but it points into a VERSIONED directory
	// (…/Caskroom/tvault/0.20.0/tvault) that the next `brew upgrade` deletes.
	// A definition holding the resolved path stops spawning after any upgrade,
	// with launchd reporting only exit status 78. The symlink is the durable
	// path, so keep it.

	passFile := strings.TrimSpace(agentPassphraseFileFlag)
	if passFile == "" {
		passFile = passphraseFilePath(cfg)
	} else {
		passFile = expandHome(passFile)
	}
	if passFile != "" {
		abs, aerr := filepath.Abs(passFile)
		if aerr != nil {
			return service.Config{}, fmt.Errorf("resolve passphrase file %s: %w", passFile, aerr)
		}
		passFile = abs
		// Fail here rather than letting the service fail invisibly at boot: a
		// missing or loose file means the agent can never unlock.
		if _, rerr := readPassphraseFile(passFile); rerr != nil {
			return service.Config{}, rerr
		}
	}

	logDir := agentLogDir(cfg)
	if logDir == "" {
		logDir = logging.StateDir()
	}
	absLogDir, err := filepath.Abs(logDir)
	if err != nil {
		return service.Config{}, fmt.Errorf("resolve log directory %s: %w", logDir, err)
	}

	// TVAULT_DIR is recorded only when it differs from the default, so the
	// definition stays portable when the user has not overridden it.
	vaultDir := ""
	if explicit := strings.TrimSpace(os.Getenv("TVAULT_DIR")); explicit != "" || vaultDirFlagSet() {
		abs, aerr := filepath.Abs(getVaultDir())
		if aerr != nil {
			return service.Config{}, fmt.Errorf("resolve vault directory: %w", aerr)
		}
		vaultDir = abs
	}

	return service.Config{
		Executable:     exe,
		VaultDir:       vaultDir,
		PassphraseFile: passFile,
		LogDir:         absLogDir,
		LogLevel:       agentLogLevel(cfg),
		Idle:           agentIdle,
	}, nil
}

// vaultDirFlagSet reports whether --vault was passed, so an explicit choice is
// baked into the service definition.
func vaultDirFlagSet() bool { return strings.TrimSpace(vaultDir) != "" }

func runAgentInstall(_ *cobra.Command, _ []string) error {
	kind, err := service.DefaultKind()
	if err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath(), err)
	}
	sc, err := serviceConfig(cfg)
	if err != nil {
		return err
	}

	if sc.PassphraseFile == "" {
		return fmt.Errorf(
			"a service has no terminal to prompt at: pass --passphrase-file <file> "+
				"or set agent.passphrase_file in %s", configPath())
	}

	body, err := service.Render(kind, sc)
	if err != nil {
		return err
	}
	path, err := service.UnitPath(kind)
	if err != nil {
		return err
	}

	if agentInstallDryRun {
		fmt.Printf("# %s definition for %s\n# %s\n\n%s", kind, sc.Executable, path, body)
		return nil
	}

	if mkErr := os.MkdirAll(sc.LogDir, 0o700); mkErr != nil {
		return fmt.Errorf("create log directory %s: %w", sc.LogDir, mkErr)
	}
	written, err := service.Write(kind, sc)
	if err != nil {
		return err
	}
	Success(fmt.Sprintf("wrote %s definition", kind))
	PrintKeyValue("Definition", written)
	PrintKeyValue("Logs", logging.Path("agent", logging.Options{Dir: sc.LogDir}))

	if agentInstallNoLoad {
		fmt.Fprintf(os.Stderr, "\nNot registered (--no-load). Load it with: tvault agent restart\n")
		return nil
	}
	if loadErr := service.Load(kind); loadErr != nil {
		return fmt.Errorf("register the service (the definition is written at %s): %w", written, loadErr)
	}
	Success("service registered and started")
	return nil
}

func runAgentUninstall(_ *cobra.Command, _ []string) error {
	kind, err := service.DefaultKind()
	if err != nil {
		return err
	}
	if unloadErr := service.Unload(kind); unloadErr != nil {
		return unloadErr
	}
	path, err := service.Remove(kind)
	if err != nil {
		return err
	}
	Success("service removed")
	PrintKeyValue("Definition", path)
	return nil
}

func runAgentRestart(_ *cobra.Command, _ []string) error {
	kind, err := service.DefaultKind()
	if err != nil {
		return err
	}
	installed, path, err := service.Installed(kind)
	if err != nil {
		return err
	}
	if !installed {
		return fmt.Errorf("no service definition at %s; run 'tvault agent install' first", path)
	}
	// Check the recorded binary before touching the service. `launchctl
	// bootstrap` happily accepts a job whose program is gone and reports
	// success, so without this the command claims "restarted" while the agent
	// never comes back — visible only as exit status 78 in `launchctl list`.
	if _, verr := service.VerifyProgram(kind); verr != nil {
		return verr
	}
	if unloadErr := service.Unload(kind); unloadErr != nil {
		return unloadErr
	}
	if loadErr := service.Load(kind); loadErr != nil {
		return loadErr
	}
	Success("service restarted")
	return nil
}

func runAgentLogs(_ *cobra.Command, _ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath(), err)
	}
	opts := logging.Options{Dir: agentLogDir(cfg)}
	path := logging.Path("agent", opts)

	if agentLogsClear {
		if err := logging.Reset("agent", opts); err != nil {
			return err
		}
		Success("agent logs cleared")
		PrintKeyValue("Path", path)
		return nil
	}

	if jsonOutput {
		info, statErr := os.Stat(path)
		out := map[string]any{"path": path, "exists": statErr == nil}
		if statErr == nil {
			out["size_bytes"] = info.Size()
		}
		return writeJSON(out)
	}

	PrintKeyValue("Path", path)
	if info, statErr := os.Stat(path); statErr == nil {
		PrintKeyValue("Size", fmt.Sprintf("%d bytes", info.Size()))
	} else {
		PrintKeyValue("Size", "not created yet")
	}
	return nil
}
