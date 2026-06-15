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
type Config struct {
	Browse BrowseConfig `yaml:"browse"`
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
