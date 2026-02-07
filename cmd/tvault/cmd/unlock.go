package cmd

import (
	"fmt"
	"os"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
	"github.com/spf13/cobra"
)

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the vault",
	Long: `Unlock the vault by entering your passphrase.

The passphrase can also be provided via the TVAULT_PASSPHRASE environment variable.`,
	RunE: runUnlock,
}

func init() {
	rootCmd.AddCommand(unlockCmd)
}

func runUnlock(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first", dir)
	}
	defer v.Close()

	passphrase := os.Getenv("TVAULT_PASSPHRASE")
	if passphrase == "" {
		passphrase, err = promptPassphrase("Enter passphrase: ")
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
	}

	if err := v.Unlock(passphrase); err != nil {
		return err
	}

	Success("Vault unlocked")
	return nil
}
