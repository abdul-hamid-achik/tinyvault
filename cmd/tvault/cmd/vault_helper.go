package cmd

import (
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
func openAndUnlockVault() (*vault.Vault, error) {
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("vault not found at %s, run 'tvault init' first", dir)
	}

	passphrase := os.Getenv("TVAULT_PASSPHRASE")
	if passphrase == "" {
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
