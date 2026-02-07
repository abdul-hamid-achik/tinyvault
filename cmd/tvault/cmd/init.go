package cmd

import (
	"fmt"
	"os"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new vault",
	Long: `Initialize a new encrypted vault.

You will be prompted to create a passphrase that protects your secrets.
A default project is created automatically.

Examples:
  tvault init
  tvault init --vault ~/my-vault`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()

	// Check if vault already exists.
	if _, err := os.Stat(dir + "/vault.db"); err == nil {
		return fmt.Errorf("vault already exists at %s", dir)
	}

	passphrase, err := promptPassphraseConfirm()
	if err != nil {
		return err
	}

	v, err := vault.Create(dir, passphrase)
	if err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}
	defer v.Close()

	fmt.Fprintln(os.Stderr)
	Success("Vault created at %s", dir)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Next steps:")
	fmt.Fprintln(os.Stderr, "  tvault set KEY VALUE    Set a secret")
	fmt.Fprintln(os.Stderr, "  tvault get KEY          Get a secret")
	fmt.Fprintln(os.Stderr, "  tvault run <command>    Run with secrets as env vars")

	return nil
}
