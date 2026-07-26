package cmd

import (
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"

	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault",
	Long:  "Lock the vault, clearing the derived key from memory.",
	RunE:  runLock,
}

func init() {
	rootCmd.AddCommand(lockCmd)
}

func runLock(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return wrapVaultOpenErr(dir, err)
	}
	defer v.Close()

	v.Lock()
	Success("Vault locked")
	return nil
}
