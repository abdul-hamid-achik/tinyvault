package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Vault key management",
	Long:  "Manage the vault encryption key.",
}

var keyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate vault passphrase",
	Long: `Re-encrypt the vault with a new passphrase.

You will be prompted for your current passphrase and then for a new passphrase.
All project encryption keys are re-encrypted under the new passphrase.

--json reports {rotated, vault_dir, rotated_at}. Neither passphrase nor any
secret value is ever included; the prompts go to stderr, so stdout stays a
single JSON document.`,
	RunE: runKeyRotate,
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyRotateCmd)
}

// keyRotateJSON is the --json shape of `tvault key rotate`. It mirrors the
// single human-readable success line: the rotation happened, and where. The
// old and new passphrases are read into locals and never leave the process,
// so there is nothing sensitive to report.
type keyRotateJSON struct {
	Rotated   bool   `json:"rotated"`
	VaultDir  string `json:"vault_dir"`
	RotatedAt string `json:"rotated_at"` // RFC3339, UTC
}

func runKeyRotate(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return wrapVaultOpenErr(dir, err)
	}
	defer v.Close()

	oldPass, err := promptPassphrase("Current passphrase: ")
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	newPass, err := promptPassphrase("New passphrase: ")
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	if newPass == "" {
		return fmt.Errorf("new passphrase cannot be empty")
	}

	confirm, err := promptPassphrase("Confirm new passphrase: ")
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	if newPass != confirm {
		return fmt.Errorf("passphrases do not match")
	}

	if err := v.RotatePassphrase(oldPass, newPass); err != nil {
		return err
	}

	if jsonOutput {
		return writeJSON(keyRotateJSON{
			Rotated:   true,
			VaultDir:  dir,
			RotatedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	Success("Passphrase rotated successfully")
	return nil
}
