package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Config is the typed view of config.yaml for settings that the global viper
// flag-binding (vault / project / verbose, wired in root.go) does not cover.
// Today that is the `agent:` block.
//
//	# ~/.tvault/config.yaml  (or $XDG_CONFIG_HOME/tvault/config.yaml)
//	agent:
//	  passphrase_command: ["/opt/homebrew/bin/op", "read", "op://Private/tvault/password"]
//	  passphrase_file: ~/.config/secrets/env
//	  log_dir: ""        # empty = $XDG_STATE_HOME/tvault
//	  log_level: info
type Config struct {
	Agent  AgentConfig  `yaml:"agent"`
	Backup BackupConfig `yaml:"backup"`
}

// BackupConfig configures rotated vault snapshots (`tvault backup` with no
// path) and the safety snapshot destructive commands take first.
type BackupConfig struct {
	// Dir receives timestamped vault-*.db snapshots. Setting it also makes
	// delete / projects delete / restore / MCP deletes snapshot first.
	Dir string `yaml:"dir"`
	// Keep is how many snapshots rotation retains (default 30).
	Keep int `yaml:"keep"`
	// Immutable marks snapshots with the macOS/BSD user-immutable flag.
	Immutable bool `yaml:"immutable"`
}

// AgentConfig holds settings for `tvault agent` and the service definitions
// `tvault agent install` generates. Explicit flags and environment variables
// always win over these. The two passphrase settings apply to every
// non-interactive unlock (CLI, MCP, agent), not just the agent; they live here
// because the agent under launchd/systemd was their first consumer.
type AgentConfig struct {
	// PassphraseCommand is a program (and its arguments) whose stdout is the
	// vault passphrase — e.g. `op read op://…` or `security
	// find-generic-password -w …`. It lets the passphrase live in a password
	// manager or the OS keychain instead of a plaintext file. It is run
	// directly, never through a shell, and wins over PassphraseFile.
	PassphraseCommand CommandSpec `yaml:"passphrase_command"`
	// PassphraseFile points at an env-style file (KEY=VALUE, `export` accepted)
	// containing TVAULT_PASSPHRASE. It exists so the agent can unlock under
	// launchd/systemd, where there is no TTY to prompt at. tvault reads the
	// file itself and refuses one that is group- or world-readable, which is
	// why the passphrase must never be inlined into a plist or unit file.
	PassphraseFile string `yaml:"passphrase_file"`
	// LogDir overrides where agent logs are written. Empty means the XDG state
	// directory ($XDG_STATE_HOME/tvault, else ~/.local/state/tvault).
	LogDir string `yaml:"log_dir"`
	// LogLevel is one of debug, info, warn, error. Empty means info.
	LogLevel string `yaml:"log_level"`
}

// CommandSpec is an argv. In YAML it is either a list (preferred: no quoting
// rules at all) or a single string that is split on whitespace with
// single/double-quote grouping. It is never handed to a shell.
type CommandSpec []string

// UnmarshalYAML accepts a scalar string or a sequence of strings.
func (c *CommandSpec) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if strings.TrimSpace(n.Value) == "" {
			*c = nil
			return nil
		}
		argv, err := splitCommandLine(n.Value)
		if err != nil {
			return err
		}
		*c = argv
		return nil
	case yaml.SequenceNode:
		var argv []string
		if err := n.Decode(&argv); err != nil {
			return err
		}
		*c = argv
		return nil
	default:
		return fmt.Errorf("line %d: passphrase_command must be a string or a list of strings", n.Line)
	}
}

// envConfigFile names an explicit config file, like --config.
const envConfigFile = "TVAULT_CONFIG"

// configPath resolves which config.yaml tvault reads, in precedence order:
//
//  1. --config
//  2. TVAULT_CONFIG
//  3. <vault dir>/config.yaml, when it exists
//  4. $XDG_CONFIG_HOME/tvault/config.yaml (else ~/.config/tvault/config.yaml),
//     when it exists and the vault is the default ~/.tvault
//  5. <vault dir>/config.yaml (the default location to create one)
//
// The XDG location is deliberately ignored for scratch vaults (TVAULT_DIR /
// --vault): it holds the operator's own unlock settings, and a test fixture or
// throwaway vault must not run their passphrase_command.
func configPath() string {
	if p := strings.TrimSpace(cfgFile); p != "" {
		return expandHome(p)
	}
	if p := strings.TrimSpace(os.Getenv(envConfigFile)); p != "" {
		return expandHome(p)
	}
	vaultCfg := filepath.Join(getVaultDir(), "config.yaml")
	if fileExists(vaultCfg) {
		return vaultCfg
	}
	if xdg := xdgConfigPath(); xdg != "" && isDefaultVaultDir() && fileExists(xdg) {
		return xdg
	}
	return vaultCfg
}

// xdgConfigPath is $XDG_CONFIG_HOME/tvault/config.yaml, falling back to
// ~/.config/tvault/config.yaml. It returns "" when neither base is known.
func xdgConfigPath() string {
	base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "tvault", "config.yaml")
}

// isDefaultVaultDir reports whether the vault in use is ~/.tvault rather than
// a scratch vault selected with TVAULT_DIR or --vault.
func isDefaultVaultDir() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	return filepath.Clean(getVaultDir()) == filepath.Join(home, defaultVaultDir)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// loadConfig reads and parses the resolved config.yaml. A missing file is
// not an error (returns the zero Config); a malformed file is, so `tvault
// doctor` can surface it.
func loadConfig() (Config, error) {
	var c Config
	data, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}
