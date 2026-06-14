package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

var (
	envEncryptIn  string
	envEncryptOut string
)

var envEncryptCmd = &cobra.Command{
	Use:   "encrypt-env",
	Short: "Encrypt a .env file using the vault's KEK",
	Long: `Encrypt a .env file and write a .env.encrypted that is safe to
commit to a repository.

The output is a self-contained binary file using the
"tvault-encrypted-v1" format. Decryption requires the vault to be
unlocked with the same passphrase that was active when the file was
created. Rotating the vault passphrase invalidates every previously
encrypted .env file (this matches RotatePassphrase semantics).

The encrypted file does NOT contain the file name of the original.
Pass --output to choose a destination; otherwise the input file with
".encrypted" appended is used.

Examples:
  tvault encrypt-env --in .env
  tvault encrypt-env --in .env.production --out config/.env.production.encrypted
  cat .env | tvault encrypt-env --in /dev/stdin --out .env.encrypted`,
	RunE: runEnvEncrypt,
}

var envDecryptCmd = &cobra.Command{
	Use:   "decrypt-env",
	Short: "Decrypt a .env.encrypted file using the vault's KEK",
	Long: `Decrypt a .env.encrypted file and print the contents to stdout
(or to --out if specified).

The vault must be unlocked. The passphrase that was active when the
file was created must still unlock the vault.

Examples:
  tvault decrypt-env --in .env.encrypted
  tvault decrypt-env --in .env.encrypted --out .env
  tvault decrypt-env --in config/.env.production.encrypted --out .env.production`,
	RunE: runEnvDecrypt,
}

func init() {
	rootCmd.AddCommand(envEncryptCmd, envDecryptCmd)
	for _, c := range []*cobra.Command{envEncryptCmd, envDecryptCmd} {
		c.Flags().StringVarP(&envEncryptIn, "in", "i", "", "Input file (default: stdin)")
		c.Flags().StringVarP(&envEncryptOut, "out", "o", "", "Output file (default: stdout for decrypt, <in>.encrypted for encrypt)")
	}
}

func runEnvEncrypt(_ *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	plaintext, err := readInput(envEncryptIn)
	if err != nil {
		return err
	}

	kek, err := v.KEK()
	if err != nil {
		return err
	}
	defer zeroBytes(kek)

	out, err := encryptedenv.Encrypt(kek, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	dest := envEncryptOut
	if dest == "" {
		if envEncryptIn == "" || envEncryptIn == "/dev/stdin" {
			return fmt.Errorf("--out is required when reading from stdin")
		}
		dest = envEncryptIn + ".encrypted"
	}

	if err := os.WriteFile(dest, out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %d bytes to %s\n", len(out), dest)
	return nil
}

func runEnvDecrypt(_ *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	data, err := readInput(envEncryptIn)
	if err != nil {
		return err
	}

	kek, err := v.KEK()
	if err != nil {
		return err
	}
	defer zeroBytes(kek)

	plaintext, err := encryptedenv.Decrypt(kek, data)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if envEncryptOut == "" {
		_, err := os.Stdout.Write(plaintext)
		return err
	}
	if err := os.WriteFile(envEncryptOut, plaintext, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", envEncryptOut, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %d bytes to %s\n", len(plaintext), envEncryptOut)
	return nil
}

func readInput(path string) ([]byte, error) {
	if path == "" || path == "/dev/stdin" {
		return os.ReadFile("/dev/stdin")
	}
	return os.ReadFile(path)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
