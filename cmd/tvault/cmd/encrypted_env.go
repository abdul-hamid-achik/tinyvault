package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

var (
	envEncryptIn         string
	envEncryptOut        string
	envEncryptRecipients []string
	envDecryptIdentity   string
)

var envEncryptCmd = &cobra.Command{
	Use:   "encrypt-env",
	Short: "Encrypt a .env file using the vault's KEK",
	Long: `Encrypt a .env file and write a .env.encrypted that is safe to
commit to a repository.

Two formats are produced depending on the flags:

  • Passphrase (v1, default): tied to the vault KEK. Decryption requires
    the vault unlocked with the same passphrase that was active when the
    file was created; rotating the passphrase invalidates it.

  • Recipient (v2, with --recipient): a commit-safe file that does NOT
    depend on the vault passphrase. A random per-file key encrypts the
    body and is wrapped to each X25519 recipient (tvault1…). Any holder
    of a matching identity — a teammate, CI, or an agent — can decrypt it
    with "decrypt-env --identity", and rotating the passphrase does not
    invalidate it. Pass --recipient multiple times for several readers.

The encrypted file does NOT contain the file name of the original.
Pass --output to choose a destination; otherwise the input file with
".encrypted" appended is used.

Examples:
  tvault encrypt-env --in .env
  tvault encrypt-env --in .env.production --out config/.env.production.encrypted
  tvault encrypt-env --in .env --recipient tvault1abc… --recipient tvault1def…
  cat .env | tvault encrypt-env --in /dev/stdin --out .env.encrypted`,
	RunE: runEnvEncrypt,
}

var envDecryptCmd = &cobra.Command{
	Use:   "decrypt-env",
	Short: "Decrypt a .env.encrypted file using the vault's KEK",
	Long: `Decrypt a .env.encrypted file and print the contents to stdout
(or to --out if specified). The format is auto-detected:

  • Passphrase (v1): the vault must be unlocked, and the passphrase that
    was active when the file was created must still unlock it.

  • Recipient (v2): pass --identity <name> to decrypt with a local
    identity instead of the passphrase. No vault unlock is required.

Examples:
  tvault decrypt-env --in .env.encrypted
  tvault decrypt-env --in .env.encrypted --out .env
  tvault decrypt-env --in .env.encrypted --identity ci --out .env
  tvault decrypt-env --in config/.env.production.encrypted --out .env.production`,
	RunE: runEnvDecrypt,
}

func init() {
	rootCmd.AddCommand(envEncryptCmd, envDecryptCmd)
	for _, c := range []*cobra.Command{envEncryptCmd, envDecryptCmd} {
		c.Flags().StringVarP(&envEncryptIn, "in", "i", "", "Input file (default: stdin)")
		c.Flags().StringVarP(&envEncryptOut, "out", "o", "", "Output file (default: stdout for decrypt, <in>.encrypted for encrypt)")
	}
	envEncryptCmd.Flags().StringArrayVar(&envEncryptRecipients, "recipient", nil,
		"X25519 recipient (tvault1…); repeatable. Produces a commit-safe v2 file that does NOT need the passphrase")
	envDecryptCmd.Flags().StringVar(&envDecryptIdentity, "identity", "",
		"Decrypt a recipient-encrypted (v2) file with this identity instead of the passphrase")
}

func runEnvEncrypt(_ *cobra.Command, _ []string) error {
	plaintext, err := readInput(envEncryptIn)
	if err != nil {
		return err
	}

	var out []byte
	if len(envEncryptRecipients) > 0 {
		// v2: recipient-based, commit-safe, no passphrase needed.
		recipients := make([][]byte, 0, len(envEncryptRecipients))
		for _, r := range envEncryptRecipients {
			pub, derr := crypto.DecodeRecipient(r)
			if derr != nil {
				return fmt.Errorf("recipient %q: %w", r, derr)
			}
			recipients = append(recipients, pub)
		}
		out, err = encryptedenv.EncryptV2(recipients, plaintext)
	} else {
		// v1: tied to the vault KEK; requires an unlocked vault.
		v, verr := openAndUnlockVault()
		if verr != nil {
			return verr
		}
		defer v.Close()
		kek, kerr := v.KEK()
		if kerr != nil {
			return kerr
		}
		defer zeroBytes(kek)
		out, err = encryptedenv.Encrypt(kek, plaintext)
	}
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
	data, err := readInput(envEncryptIn)
	if err != nil {
		return err
	}

	ver, err := encryptedenv.FileVersion(data)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	var plaintext []byte
	switch {
	case ver == 2 || envDecryptIdentity != "":
		// v2: recipient-based. Decrypt with a local identity, no passphrase.
		if envDecryptIdentity == "" {
			return fmt.Errorf("this file is recipient-encrypted (v2); pass --identity <name> to decrypt it")
		}
		keyPath, kerr := resolveIdentityFile(envDecryptIdentity)
		if kerr != nil {
			return kerr
		}
		id, ierr := loadIdentity(keyPath)
		if ierr != nil {
			return fmt.Errorf("load identity %q: %w", envDecryptIdentity, ierr)
		}
		plaintext, err = encryptedenv.DecryptV2(id, data)
	default:
		// v1: tied to the vault KEK; requires an unlocked vault.
		v, verr := openAndUnlockVault()
		if verr != nil {
			return verr
		}
		defer v.Close()
		kek, kerr := v.KEK()
		if kerr != nil {
			return kerr
		}
		defer zeroBytes(kek)
		plaintext, err = encryptedenv.Decrypt(kek, data)
	}
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
