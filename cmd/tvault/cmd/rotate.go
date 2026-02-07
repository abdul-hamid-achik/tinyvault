package cmd

import (
	"fmt"
	"os"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
	"github.com/spf13/cobra"
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
All project encryption keys are re-encrypted under the new passphrase.`,
	RunE: runKeyRotate,
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyRotateCmd)
}

func runKeyRotate(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first", dir)
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

	Success("Passphrase rotated successfully")
	return nil
}
