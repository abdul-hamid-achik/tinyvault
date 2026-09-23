package cmd

import (
	"errors"
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

// errPassphraseFileUnusable marks a passphrase file that exists but holds no
// usable TVAULT_PASSPHRASE (unparseable, or the key is absent). For an
// explicitly configured file that is a hard error; for the implicit
// conventional file it only means "this file is not the unlock source".
var errPassphraseFileUnusable = errors.New("passphrase file has no usable TVAULT_PASSPHRASE")

// passphraseFilePath resolves which env file to read, in precedence order:
// the TVAULT_PASSPHRASE_FILE environment variable, then the config's
// agent.passphrase_file, then ~/.config/secrets/env when that file exists.
// It returns "" when none of those apply.
//
// A leading ~ is expanded so config.yaml can hold the portable
// "~/.config/secrets/env" rather than a machine-specific absolute path.
func passphraseFilePath(cfg Config) string {
	path, _ := passphraseFileSource(cfg)
	return path
}

// passphraseFileSource is passphraseFilePath plus whether the path is the
// implicit conventional fallback rather than something the operator named.
func passphraseFileSource(cfg Config) (path string, implicit bool) {
	path = strings.TrimSpace(os.Getenv(envPassphraseFile))
	if path == "" {
		path = strings.TrimSpace(cfg.Agent.PassphraseFile)
	}
	if path != "" {
		return expandHome(path), false
	}
	if path = conventionalPassphraseFileIfPresent(); path != "" {
		return path, true
	}
	return "", false
}

func conventionalPassphraseFileIfPresent() string {
	// Scratch vaults (TVAULT_DIR / --vault) must not inherit the operator's
	// login passphrase; that turns "locked" into "wrong passphrase" in tests
	// and isolated fixtures.
	if !isDefaultVaultDir() {
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
		return "", fmt.Errorf("%w: parse passphrase file %s: %w", errPassphraseFileUnusable, path, err)
	}
	for _, e := range parsed.Entries {
		if e.Key == passphraseFileKey {
			if strings.TrimSpace(e.Value) == "" {
				return "", fmt.Errorf("%s in %s is empty", passphraseFileKey, path)
			}
			return e.Value, nil
		}
	}
	return "", fmt.Errorf("%w: %s not found in %s", errPassphraseFileUnusable, passphraseFileKey, path)
}

// Passphrase sources, as reported by passphraseSource.
const (
	passSourceEnv     = "env"
	passSourceCommand = "command"
	passSourceFile    = "file"
)

// passphrasePlan is the one non-interactive source an unlock would use.
type passphrasePlan struct {
	kind     string   // passSourceEnv / passSourceCommand / passSourceFile, or "" for none
	argv     []string // command sources
	origin   string   // where a command came from, for errors
	path     string   // file sources
	implicit bool     // the conventional ~/.config/secrets/env fallback
}

// resolvePassphrasePlan picks the non-interactive passphrase source without
// running a command or reading a secret. Environment variables beat config,
// and within each layer a command beats a file:
//
//  1. TVAULT_PASSPHRASE
//  2. TVAULT_PASSPHRASE_COMMAND
//  3. TVAULT_PASSPHRASE_FILE
//  4. agent.passphrase_command (config.yaml)
//  5. agent.passphrase_file (config.yaml)
//  6. ~/.config/secrets/env, only for the default vault and only when it
//     actually defines TVAULT_PASSPHRASE
//
// So moving the passphrase into a password manager is one config line, and it
// takes effect even while an old file still exists — yet a caller that names
// an explicit source in its environment (CI, an MCP host stanza) still gets
// exactly that source.
func resolvePassphrasePlan(cfg Config) (passphrasePlan, error) {
	if os.Getenv("TVAULT_PASSPHRASE") != "" {
		return passphrasePlan{kind: passSourceEnv}, nil
	}
	if strings.TrimSpace(os.Getenv(envPassphraseCommand)) != "" {
		argv, origin, err := passphraseCommand(cfg)
		return passphrasePlan{kind: passSourceCommand, argv: argv, origin: origin}, err
	}
	if p := strings.TrimSpace(os.Getenv(envPassphraseFile)); p != "" {
		return passphrasePlan{kind: passSourceFile, path: expandHome(p)}, nil
	}
	if len(cfg.Agent.PassphraseCommand) > 0 {
		argv, origin, err := passphraseCommand(cfg)
		return passphrasePlan{kind: passSourceCommand, argv: argv, origin: origin}, err
	}
	path, implicit := passphraseFileSource(cfg)
	if path == "" {
		return passphrasePlan{}, nil
	}
	if implicit {
		if _, err := readPassphraseFile(path); errors.Is(err, errPassphraseFileUnusable) {
			// Once the passphrase has moved out of it, the conventional file is
			// just the user's shell environment, not an unlock source.
			return passphrasePlan{}, nil
		}
	}
	return passphrasePlan{kind: passSourceFile, path: path, implicit: implicit}, nil
}

// passphraseSource reports which non-interactive source would supply the
// passphrase (see resolvePassphrasePlan), or "" when only a TTY prompt
// remains. It never runs a command. A misconfigured command (e.g. an untrusted
// config file) still reports passSourceCommand, so the unlock itself surfaces
// the error instead of silently prompting.
func passphraseSource(cfg Config) string {
	plan, err := resolvePassphrasePlan(cfg)
	if err != nil {
		return passSourceCommand
	}
	return plan.kind
}

// nonInteractivePassphrase returns the passphrase for a non-interactive unlock
// from the source resolvePassphrasePlan picks. It returns ("", nil) when
// nothing is configured, leaving the caller to prompt or fail closed as it
// sees fit. A configured source that fails (a loose file, a helper that exits
// non-zero) is a hard error rather than a silent fall-through to the prompt,
// so a broken deployment surfaces instead of hanging on a prompt.
func nonInteractivePassphrase(cfg Config) (string, error) {
	plan, err := resolvePassphrasePlan(cfg)
	if err != nil {
		return "", err
	}
	switch plan.kind {
	case passSourceEnv:
		return os.Getenv("TVAULT_PASSPHRASE"), nil
	case passSourceCommand:
		return runPassphraseCommand(plan.argv, plan.origin)
	case passSourceFile:
		return readPassphraseFile(plan.path)
	default:
		return "", nil
	}
}
