package cmd

import (
	"os"
	"path/filepath"

	yaml "go.yaml.in/yaml/v3"
)

// Config is the typed view of ~/.tvault/config.yaml for settings that the
// global viper flag-binding (vault / project / verbose, wired in root.go)
// does not cover. Today that is the `browse:` block (the key is kept as
// `browse:` for backwards compatibility), which supplies defaults for the
// interactive studio's flags (`tvault studio`, aliases `browse`/`ui`).
//
//	# ~/.tvault/config.yaml
//	browse:
//	  no_anim: false
//	  single_pane: false
//	  audit_limit: 100
//	agent:
//	  passphrase_file: ~/.config/secrets/env
//	  log_dir: ""        # empty = $XDG_STATE_HOME/tvault
//	  log_level: info
type Config struct {
	Browse BrowseConfig `yaml:"browse"`
	Agent  AgentConfig  `yaml:"agent"`
}

// AgentConfig holds settings for `tvault agent` and the service definitions
// `tvault agent install` generates. Explicit flags and environment variables
// always win over these.
type AgentConfig struct {
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

// BrowseConfig holds default settings for `tvault studio` (under the
// `browse:` config key, kept for backwards compatibility). Explicit
// command-line flags always win over these.
type BrowseConfig struct {
	NoAnim     bool `yaml:"no_anim"`
	SinglePane bool `yaml:"single_pane"`
	AuditLimit int  `yaml:"audit_limit"`
}

func configPath() string { return filepath.Join(getVaultDir(), "config.yaml") }

// loadConfig reads and parses ~/.tvault/config.yaml. A missing file is not
// an error (returns the zero Config); a malformed file is, so `tvault
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
