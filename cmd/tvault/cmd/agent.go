package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
	"github.com/abdul-hamid-achik/tinyvault/internal/logging"
)

var (
	agentIdle         time.Duration
	agentRequireToken bool
	agentTokenFile    string
	agentLogDirFlag   string
	agentLogLevelFlag string
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run a local agent that holds the vault unlocked for fast, prompt-free access",
	Long: `Run a local agent (unix only) that unlocks the vault once and serves
secret reads over a private unix-domain socket, so subsequent
` + "`tvault get/env/run`" + ` (and shell hooks) skip the passphrase prompt and the
~200ms Argon2id key derivation.

The agent caches only the KEK — not an open database — and reopens the vault
per request, so direct CLI access keeps working between requests. The socket
is 0600 inside the 0700 vault dir and accepts only same-uid peers. The KEK
lives in memory for the agent's lifetime, so it auto-locks after an idle
period (default 15m) and zeros the KEK on stop/idle/signal.

The agent runs in the FOREGROUND; background it yourself (& , nohup, systemd
Type=simple, launchd). Pair it with ` + "`tvault hook`" + `.

Examples:
  tvault agent start
  tvault agent start --idle 1h &
  tvault agent status --json
  tvault agent stop`,
}

var agentStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Unlock the vault and serve secrets over a local socket (foreground)",
	RunE:  runAgentStart,
}

var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the agent is running",
	RunE:  runAgentStatus,
}

var agentStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running agent (zeroing its KEK)",
	RunE:  runAgentStop,
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.AddCommand(agentStartCmd, agentStatusCmd, agentStopCmd)
	agentStartCmd.Flags().DurationVar(&agentIdle, "idle", 15*time.Minute, "Auto-lock after this idle duration (0 = never)")
	agentStartCmd.Flags().BoolVar(&agentRequireToken, "require-token", false,
		"Deny socket requests without a valid capability token from --token-file (privilege separation for OS-confined delegates)")
	agentStartCmd.Flags().StringVar(&agentTokenFile, "token-file", "",
		"0600 file of `token[:project]` lines for --require-token (SIGHUP reloads it)")
	agentStartCmd.Flags().StringVar(&agentLogDirFlag, "log-dir", "",
		"Directory for agent logs (default $XDG_STATE_HOME/tvault)")
	agentStartCmd.Flags().StringVar(&agentLogLevelFlag, "log-level", "",
		"Agent log level: debug, info, warn or error (default info)")
}

// agentLogDir resolves the log directory: flag, then TVAULT_LOG_DIR, then
// config, then the XDG state directory (resolved inside internal/logging).
func agentLogDir(cfg Config) string {
	if v := strings.TrimSpace(agentLogDirFlag); v != "" {
		return expandHome(v)
	}
	if v := strings.TrimSpace(os.Getenv("TVAULT_LOG_DIR")); v != "" {
		return expandHome(v)
	}
	return expandHome(strings.TrimSpace(cfg.Agent.LogDir))
}

// agentLogLevel resolves the log level with the same precedence as agentLogDir.
func agentLogLevel(cfg Config) string {
	if v := strings.TrimSpace(agentLogLevelFlag); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("TVAULT_LOG_LEVEL")); v != "" {
		return v
	}
	return strings.TrimSpace(cfg.Agent.LogLevel)
}

func runAgentStart(_ *cobra.Command, _ []string) error {
	if !agent.Supported() {
		return agent.ErrUnsupportedPlatform
	}
	if agentRequireToken && agentTokenFile == "" {
		return fmt.Errorf("--require-token needs --token-file")
	}
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath(), err)
	}
	// A configured passphrase file counts as a usable unlock source: it is how
	// the agent starts under launchd/systemd, where there is neither a TTY nor
	// an inherited TVAULT_PASSPHRASE.
	if !term.IsTerminal(int(os.Stdin.Fd())) &&
		os.Getenv("TVAULT_PASSPHRASE") == "" && passphraseFilePath(cfg) == "" {
		return fmt.Errorf(
			"agent start needs a TTY, TVAULT_PASSPHRASE, or %s (see 'tvault agent install')",
			envPassphraseFile)
	}

	logger, logCloser, err := logging.New("agent", logging.Options{
		Dir:   agentLogDir(cfg),
		Level: agentLogLevel(cfg),
		// Mirror to stderr only in the foreground: under launchd/systemd the
		// supervisor already captures stderr, and a copy would double-write.
		Stderr: term.IsTerminal(int(os.Stderr.Fd())),
	})
	if err != nil {
		return err
	}
	defer func() { _ = logCloser.Close() }()

	v, err := openAndUnlockVault()
	if err != nil {
		logger.Error("agent failed to unlock the vault", "err", err)
		return err
	}
	kek, err := v.KEK()
	if err != nil {
		_ = v.Close()
		return err
	}
	project := resolveProject(v, projectName)
	_ = v.Close() // release the bbolt lock; the agent reopens per request

	// agent.Start can fail after the vault is unlocked but before it logs
	// anything itself (a too-long socket path, a held lock, a bad token file).
	// Record that here or the log ends at "unlocked" with no explanation — the
	// worst case being a service supervisor that keeps restarting silently.
	if startErr := agent.Start(agent.Options{
		Dir:          getVaultDir(),
		KEK:          kek,
		Project:      project,
		Idle:         agentIdle,
		RequireToken: agentRequireToken,
		TokenFile:    agentTokenFile,
		Logger:       logger,
		OnReady: func(socket string, pid int) {
			idle := "disabled"
			if agentIdle > 0 {
				idle = agentIdle.String()
			}
			fmt.Fprintf(os.Stderr, "tvault agent listening at %s (pid %d, idle %s). Press Ctrl-C to stop.\n", socket, pid, idle)
		},
	}); startErr != nil {
		logger.Error("agent failed to start", "err", startErr)
		return startErr
	}
	return nil
}

func runAgentStatus(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()
	c, err := agent.Dial(dir, 2*time.Second)
	if err != nil {
		if errors.Is(err, agent.ErrUnsupportedPlatform) {
			return err
		}
		_, statErr := os.Stat(filepath.Join(dir, agent.SocketName))
		stale := statErr == nil
		if jsonOutput {
			return writeJSON(map[string]any{"running": false, "stale_socket": stale})
		}
		if stale {
			fmt.Fprintln(os.Stderr, "agent not running (stale socket present; run: tvault agent stop)")
		} else {
			fmt.Fprintln(os.Stderr, "agent not running")
		}
		return nil
	}
	st, err := c.Status()
	if err != nil {
		return fmt.Errorf("agent status: %w", err)
	}
	if jsonOutput {
		return writeJSON(map[string]any{
			"running": true, "pid": st.PID, "socket": st.Socket, "project": st.Project,
			"uptime_seconds": st.UptimeSeconds, "idle_remaining_seconds": st.IdleRemainingSeconds,
		})
	}
	Success("agent running")
	PrintKeyValue("PID", fmt.Sprintf("%d", st.PID))
	PrintKeyValue("Socket", st.Socket)
	PrintKeyValue("Project", st.Project)
	PrintKeyValue("Uptime", (time.Duration(st.UptimeSeconds) * time.Second).String())
	if st.IdleRemainingSeconds > 0 {
		PrintKeyValue("Idle-locks in", (time.Duration(st.IdleRemainingSeconds) * time.Second).String())
	}
	return nil
}

func runAgentStop(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()
	c, err := agent.Dial(dir, 2*time.Second)
	if err != nil {
		if errors.Is(err, agent.ErrUnsupportedPlatform) {
			return err
		}
		return agent.ErrAgentNotRunning
	}
	if err := c.Stop(); err != nil {
		return fmt.Errorf("stop agent: %w", err)
	}
	Success("agent stopped")
	return nil
}
