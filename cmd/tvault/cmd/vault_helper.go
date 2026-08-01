package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

const defaultVaultDir = ".tvault"

// getVaultDir returns the vault directory path.
// Priority: --vault flag > TVAULT_DIR env > ~/.tvault
func getVaultDir() string {
	if vaultDir != "" {
		return vaultDir
	}
	if dir := os.Getenv("TVAULT_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultVaultDir
	}
	return home + "/" + defaultVaultDir
}

// openAndUnlockVault opens the vault at the configured directory and unlocks it.
// It tries TVAULT_PASSPHRASE env var first (for CI), then prompts interactively.
//
// When stdin is not a TTY and no TVAULT_PASSPHRASE is set, it cannot unlock and
// must NOT prompt (a non-interactive process would hang or emit an
// indistinguishable "failed to read passphrase" error). Instead it fails fast
// with a vault.ErrLocked-wrapped error so the exit-code mapper produces exit 3.
// Under --json it prints {"error":"vault_locked","locked":true} on stdout and
// silences cobra's stderr error print, so a non-interactive agent (e.g. Cortex)
// gets a clean, deterministic "vault locked" signal.
// wrapVaultOpenErr turns a vault.Open failure into a user-facing error.
//
// Only vault.ErrNotInitialized warrants the `tvault init` hint. A busy vault
// (another tvault process holds bbolt's exclusive lock) is a fully initialized
// vault, so telling the user to re-initialize it is both wrong and alarming —
// it points at the vault when the real fix is to stop the other process. The
// original error is always wrapped so callers and the exit-code mapper can
// still match on it.
func wrapVaultOpenErr(dir string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, vault.ErrVaultBusy) {
		return err
	}
	return fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", dir, err)
}

func openAndUnlockVault() (*vault.Vault, error) {
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return nil, wrapVaultOpenErr(dir, err)
	}

	// A configured passphrase file is consulted before the TTY: it is how a
	// daemonized agent (launchd/systemd), which inherits no TVAULT_PASSPHRASE,
	// unlocks at all. A malformed or loosely-permissioned file is a hard error
	// rather than a silent fall-through to the prompt, so a broken deployment
	// surfaces instead of hanging a service on a prompt nobody can answer.
	cfg, cfgErr := loadConfig()
	if cfgErr != nil {
		_ = v.Close()
		return nil, fmt.Errorf("read %s: %w", configPath(), cfgErr)
	}
	passphrase, err := passphraseFromEnvOrFile(cfg)
	if err != nil {
		_ = v.Close()
		return nil, err
	}
	if passphrase == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			// Non-interactive and no passphrase env: fail fast with the
			// locked signal instead of prompting (which would error out
			// with an opaque "operation not supported by device").
			return nil, nonInteractiveLockedError(v)
		}
		// The open above proved the vault exists (so we never prompt for a
		// vault that isn't there), but bbolt's lock is process-wide and a human
		// at a prompt is an unbounded wait — holding it would block every other
		// tvault on the machine until they type. Drop it, prompt, then retake.
		if closeErr := v.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to release the vault before prompting: %w", closeErr)
		}
		passphrase, err = promptPassphrase("Enter passphrase: ")
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		if v, err = vault.Open(dir); err != nil {
			return nil, wrapVaultOpenErr(dir, err)
		}
	}

	if err := v.Unlock(passphrase); err != nil {
		v.Close()
		return nil, err
	}

	return v, nil
}

// nonInteractiveLockedError emits the deterministic "vault locked" signal for
// a non-interactive caller and returns a vault.ErrLocked-wrapped error so the
// exit-code mapper produces exit 3. Under --json it writes
// {"error":"vault_locked","locked":true} to stdout and silences cobra's stderr
// error print (so nothing reaches stderr, per the contract); otherwise it
// returns a human-readable error that cobra prints to stderr. The vault handle
// is closed.
func nonInteractiveLockedError(v *vault.Vault) error {
	v.Close()
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(map[string]any{
			"error":  "vault_locked",
			"locked": true,
		}); err != nil {
			// Best-effort: we are already returning a locked error below.
			_ = err
		}
		// Silence cobra's "Error: ..." stderr print for this invocation;
		// we already produced the contract JSON on stdout.
		rootCmd.SilenceErrors = true
	}
	// agentReachable() is an observation, not a routing decision, so it holds
	// even under --no-agent, and it costs nothing when no socket exists (the
	// dial fails on the missing path). This is already a failure path.
	return fmt.Errorf("%w: %s", vault.ErrLocked, lockedRemedy(agentReachable()))
}

// lockedRemedy explains how this process could actually unlock, for the state
// it can observe.
//
// It must never offer "start 'tvault agent'" as the remedy for a command that
// needs the key. The agent's wire protocol is read-only (get / getall /
// getselected / status / stop) and it never hands out the KEK, so `set`,
// `delete`, `import`, `rotate` and every other unlock-requiring command still
// needs the passphrase while an agent is happily serving reads.
//
// The old fixed advice was most misleading exactly where it was most often
// read: a `tvault set` nested inside `tvault run`, whose child inherits no
// TVAULT_* variable (processenv.Sanitize) and whose user already has an agent
// running. "start 'tvault agent'" sent people debugging a healthy socket
// instead of supplying a credential, so both facts are stated here.
func lockedRemedy(agentRunning bool) string {
	clauses := []string{"stdin is not a TTY, so tvault cannot prompt"}
	if agentRunning {
		clauses = append(clauses,
			"the running tvault agent serves reads only (get/env/run) and never hands out the key, "+
				"so this command needs the passphrase itself")
	}
	clauses = append(clauses,
		"set TVAULT_PASSPHRASE, point TVAULT_PASSPHRASE_FILE (or agent.passphrase_file) at a 0600 env file, or run in a TTY")
	if !agentRunning && agent.Supported() {
		clauses = append(clauses,
			"starting 'tvault agent' makes read commands prompt-free but never unlocks a write")
	}
	clauses = append(clauses,
		"a child of 'tvault run' or MCP exec inherits no TVAULT_* variable and must supply its own credential")
	return strings.Join(clauses, "; ")
}

// resolveProject determines which project to use.
// Priority: --project flag > stored current project > "default"
func resolveProject(v *vault.Vault, flagProject string) string {
	if flagProject != "" {
		return flagProject
	}
	if current, err := v.GetCurrentProject(); err == nil && current != "" {
		return current
	}
	return "default"
}

// promptPassphrase reads a passphrase from the terminal with echo disabled.
func promptPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// promptPassphraseConfirm prompts for a passphrase twice and ensures they match.
func promptPassphraseConfirm() (string, error) {
	pass, err := promptPassphrase("Enter passphrase: ")
	if err != nil {
		return "", err
	}
	if pass == "" {
		return "", fmt.Errorf("passphrase cannot be empty")
	}
	confirm, err := promptPassphrase("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if pass != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}
	return pass, nil
}

// resolveInitPassphrase returns the passphrase for `tvault init`.
// It honors TVAULT_PASSPHRASE for non-interactive / CI use; otherwise
// it prompts twice and verifies the values match.
func resolveInitPassphrase() (string, error) {
	if env := os.Getenv("TVAULT_PASSPHRASE"); env != "" {
		return env, nil
	}
	return promptPassphraseConfirm()
}
