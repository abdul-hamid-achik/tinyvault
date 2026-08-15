package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

// envPassphraseFile names an env-style file holding TVAULT_PASSPHRASE.
//
// It exists for surfaces that must unlock without a TTY — chiefly `tvault
// agent` running under launchd or systemd. The alternative, inlining the
// passphrase into a launchd plist or a systemd unit, writes the secret into a
// file that is world-readable by default on macOS and ends up in backups; this
// keeps the secret in a file the user already protects (e.g. the
// ~/.config/secrets/env that a shell sources at startup) and makes tvault
// verify that protection before reading it.
const envPassphraseFile = "TVAULT_PASSPHRASE_FILE" //nolint:gosec // G101: a variable name, not a credential

// passphraseFileKey is the variable read out of the resolved file.
const passphraseFileKey = "TVAULT_PASSPHRASE" //nolint:gosec // G101: a variable name, not a credential

// conventionalPassphraseFile is the well-known env file tvault agent install
// and launchd/systemd units already document. MCP hosts and GUI-launched
// harnesses rarely inherit TVAULT_* from a login shell; if this file exists
// we treat it as the implicit last-resort unlock path so `tvault get` /
// `tvault run` work without a per-tool env stanza.
const conventionalPassphraseFile = "~/.config/secrets/env" //nolint:gosec // G101: a path, not a credential

// passphraseFilePath resolves which env file to read, in precedence order:
// the TVAULT_PASSPHRASE_FILE environment variable, then the config's
// agent.passphrase_file, then ~/.config/secrets/env when that file exists.
// It returns "" when none of those apply.
//
// A leading ~ is expanded so config.yaml can hold the portable
// "~/.config/secrets/env" rather than a machine-specific absolute path.
func passphraseFilePath(cfg Config) string {
	path := strings.TrimSpace(os.Getenv(envPassphraseFile))
	if path == "" {
		path = strings.TrimSpace(cfg.Agent.PassphraseFile)
	}
	if path == "" {
		path = conventionalPassphraseFileIfPresent()
	}
	return expandHome(path)
}

func conventionalPassphraseFileIfPresent() string {
	// Scratch vaults (TVAULT_DIR / --vault) must not inherit the operator's
	// login passphrase; that turns "locked" into "wrong passphrase" in tests
	// and isolated fixtures.
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if getVaultDir() != home+"/"+defaultVaultDir {
		return ""
	}
	candidate := expandHome(conventionalPassphraseFile)
	info, err := os.Stat(candidate)
	if err != nil || info.IsDir() {
		return ""
	}
	return candidate
}

// expandHome turns a leading ~ or ~/ into the user's home directory. A path
// that does not start with ~ is returned unchanged, as is any path when the
// home directory cannot be determined.
func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}

// readPassphraseFile reads TVAULT_PASSPHRASE out of an env-style file.
//
// The file must not be readable by group or others: it holds the passphrase
// that guards every secret in the vault, so a permissive mode is refused
// outright rather than warned about. Errors describe the file and its mode and
// never include any value read from it.
func readPassphraseFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read passphrase file %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("passphrase file %s is a directory", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf(
			"passphrase file %s is readable by group or others (mode %#o); tighten it with: chmod 600 %s",
			path, perm, path)
	}

	// Read and parse the bytes directly rather than going through
	// dotenv.ParseFile: that helper enforces the .env naming convention, which
	// does not apply to a general secrets file such as ~/.config/secrets/env.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read passphrase file %s: %w", path, err)
	}
	parsed, err := dotenv.ParseBytes(filepath.Base(path), data)
	if err != nil {
		return "", fmt.Errorf("parse passphrase file %s: %w", path, err)
	}
	for _, e := range parsed.Entries {
		if e.Key == passphraseFileKey {
			if strings.TrimSpace(e.Value) == "" {
				return "", fmt.Errorf("%s in %s is empty", passphraseFileKey, path)
			}
			return e.Value, nil
		}
	}
	return "", fmt.Errorf("%s not found in %s", passphraseFileKey, path)
}

// passphraseFromEnvOrFile returns the passphrase for a non-interactive unlock.
//
// Precedence is TVAULT_PASSPHRASE (already in the environment, e.g. exported by
// a shell) over the passphrase file, so an explicit env var still wins and the
// file is the fallback for daemons that inherit no such variable. It returns
// ("", nil) when neither source is configured, leaving the caller to prompt or
// fail closed as it sees fit.
func passphraseFromEnvOrFile(cfg Config) (string, error) {
	if pass := os.Getenv("TVAULT_PASSPHRASE"); pass != "" {
		return pass, nil
	}
	path := passphraseFilePath(cfg)
	if path == "" {
		return "", nil
	}
	return readPassphraseFile(path)
}
