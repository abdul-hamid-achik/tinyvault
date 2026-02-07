package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var backupCmd = &cobra.Command{
	Use:   "backup <path>",
	Short: "Copy encrypted vault to a backup location",
	Long: `Create a backup of the encrypted vault database file.

The backup is a direct copy of the encrypted vault.db file.

Examples:
  tvault backup ~/backups/vault.db.bak
  tvault backup /mnt/usb/vault-backup.db`,
	Args: cobra.ExactArgs(1),
	RunE: runBackup,
}

var (
	restoreYes bool
)

var restoreCmd = &cobra.Command{
	Use:   "restore <path>",
	Short: "Restore vault from a backup",
	Long: `Restore the vault database from a backup file.

WARNING: This will overwrite the current vault database.

Examples:
  tvault restore ~/backups/vault.db.bak`,
	Args: cobra.ExactArgs(1),
	RunE: runRestore,
}

func init() {
	rootCmd.AddCommand(backupCmd)
	rootCmd.AddCommand(restoreCmd)
	restoreCmd.Flags().BoolVarP(&restoreYes, "yes", "y", false, "Skip confirmation prompt")
}

func runBackup(_ *cobra.Command, args []string) error {
	dir := getVaultDir()
	src := filepath.Join(dir, "vault.db")

	if _, err := os.Stat(src); os.IsNotExist(err) {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first", dir)
	}

	dst := args[0]
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	Success("Vault backed up to %s", dst)
	return nil
}

func runRestore(_ *cobra.Command, args []string) error {
	src := args[0]
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", src)
	}

	dir := getVaultDir()
	dst := filepath.Join(dir, "vault.db")

	if !restoreYes {
		Warning("This will overwrite the current vault database.")
		if !PromptConfirm("Restore from backup?") {
			Info("Canceled")
			return nil
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}

	Success("Vault restored from %s", src)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
