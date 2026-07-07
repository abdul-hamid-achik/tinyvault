package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/term"

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
func openAndUnlockVault() (*vault.Vault, error) {
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		// Wrap the original (vault.ErrNotInitialized) so callers and the
		// exit-code mapper can detect "not initialized" (exit 5).
		return nil, fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", dir, err)
	}

	passphrase := os.Getenv("TVAULT_PASSPHRASE")
	if passphrase == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			// Non-interactive and no passphrase env: fail fast with the
			// locked signal instead of prompting (which would error out
			// with an opaque "operation not supported by device").
			return nil, nonInteractiveLockedError(v)
		}
		passphrase, err = promptPassphrase("Enter passphrase: ")
		if err != nil {
			v.Close()
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
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
	return fmt.Errorf("vault is locked: set TVAULT_PASSPHRASE, start 'tvault agent', or run in a TTY: %w", vault.ErrLocked)
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
