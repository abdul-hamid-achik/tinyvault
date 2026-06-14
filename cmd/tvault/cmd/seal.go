package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

// seal/open are the symmetric CLI pair for the recipient layer, mirroring the
// vault_seal_for_recipients MCP tool and the git clean/smudge filters. `seal`
// reads a project straight from the vault and emits a commit-safe v2 blob
// (no plaintext .env ever touches disk); `open` decrypts such a blob with a
// local identity. Both share the v2 format used by encrypt-env --recipient.

var (
	sealRecipients []string
	sealKeys       []string
	sealOut        string

	openIn       string
	openIdentity string
	openOut      string
)

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal a project's secrets to X25519 recipients (commit-safe ciphertext)",
	Long: `Read a project's secrets straight from the vault and write a v2
.env.encrypted blob sealed to one or more X25519 recipients. Only a holder of
a matching identity can open it (with 'tvault open' or 'decrypt-env
--identity') -- no passphrase, and passphrase rotation does not invalidate it.

Unlike 'encrypt-env', no plaintext .env file is produced on the way: the
secrets go straight from the unlocked vault into ciphertext. Recipients come
from --recipient, or from a committed .tvault-recipients file when none are
given.

Examples:
  tvault seal --recipient tvault1… > .env.encrypted
  tvault seal -p prod --key DATABASE_URL --key API_KEY -o prod.encrypted
  tvault seal | ssh deploy-host 'tvault open --identity host > .env'`,
	RunE: runSeal,
}

var openCmd = &cobra.Command{
	Use:   "open",
	Short: "Open a recipient-sealed (v2) blob with an identity",
	Long: `Decrypt a v2 blob produced by 'tvault seal', 'encrypt-env
--recipient', or the git clean filter, using a local identity, and print the
dotenv body (or write it with --out). No passphrase or vault unlock is needed.

The identity is --identity, else $TVAULT_IDENTITY, else "default", resolved
under ~/.tvault/identities/<name>.key. This is the inverse of 'tvault seal'.

Examples:
  tvault open --in .env.encrypted --identity ci --out .env
  cat .env.encrypted | tvault open > .env`,
	RunE: runOpen,
}

func init() {
	rootCmd.AddCommand(sealCmd, openCmd)
	sealCmd.Flags().StringArrayVarP(&sealRecipients, "recipient", "r", nil,
		"Recipient (tvault1…); repeatable. Defaults to .tvault-recipients when omitted")
	sealCmd.Flags().StringArrayVar(&sealKeys, "key", nil,
		"Secret key to include; repeatable. Default: all secrets in the project")
	sealCmd.Flags().StringVarP(&sealOut, "out", "o", "", "Write the sealed blob here (default: stdout)")

	openCmd.Flags().StringVarP(&openIn, "in", "i", "", "Sealed input file (default: stdin)")
	openCmd.Flags().StringVar(&openIdentity, "identity", "",
		"Identity name to decrypt with (default: $TVAULT_IDENTITY, else 'default')")
	openCmd.Flags().StringVarP(&openOut, "out", "o", "", "Write the decrypted dotenv here (default: stdout)")
}

func runSeal(_ *cobra.Command, _ []string) error {
	recipients, source, err := resolveSealRecipients()
	if err != nil {
		return err
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients: pass --recipient tvault1… or add them to .tvault-recipients")
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)
	all, err := v.GetAllSecrets(project)
	if err != nil {
		return fmt.Errorf("read project %q: %w", project, err)
	}
	selected, err := selectSecretKeys(all, sealKeys)
	if err != nil {
		return err
	}

	sealed, err := encryptedenv.EncryptV2(recipients, dotenv.Marshal(selected))
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	recordAudit(v, "secret.seal", "project", project, map[string]any{
		"recipients": len(recipients),
		"keys":       len(selected),
		"via":        source,
	})

	if sealOut == "" {
		_, werr := os.Stdout.Write(sealed)
		return werr
	}
	if err := os.WriteFile(sealOut, sealed, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", sealOut, err)
	}
	fmt.Fprintf(os.Stderr, "Sealed %d secret(s) to %d recipient(s) → %s\n", len(selected), len(recipients), sealOut)
	return nil
}

func runOpen(_ *cobra.Command, _ []string) error {
	data, err := readInput(openIn)
	if err != nil {
		return err
	}

	name := openIdentity
	if name == "" {
		name = strings.TrimSpace(os.Getenv("TVAULT_IDENTITY"))
	}
	keyPath, err := resolveIdentityFile(name)
	if err != nil {
		return err
	}
	id, err := loadIdentity(keyPath)
	if err != nil {
		return fmt.Errorf("load identity %q: %w", name, err)
	}

	ver, err := encryptedenv.FileVersion(data)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if ver != 2 {
		return fmt.Errorf("open handles recipient-sealed (v2) blobs; this is v%d — use `tvault decrypt-env` for passphrase files", ver)
	}
	plaintext, err := encryptedenv.DecryptV2(id, data)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	if openOut == "" {
		_, werr := os.Stdout.Write(plaintext)
		return werr
	}
	if err := os.WriteFile(openOut, plaintext, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", openOut, err)
	}
	fmt.Fprintf(os.Stderr, "Opened with identity %q → %s\n", name, openOut)
	return nil
}

// resolveSealRecipients returns the recipients to seal to: the --recipient
// flags if given, otherwise a committed .tvault-recipients file. Being outside
// a git repo is not an error here (the caller reports "no recipients"), but a
// malformed recipients file is.
func resolveSealRecipients() ([][]byte, string, error) {
	if len(sealRecipients) > 0 {
		recipients := make([][]byte, 0, len(sealRecipients))
		for _, r := range sealRecipients {
			pub, err := crypto.DecodeRecipient(r)
			if err != nil {
				return nil, "", fmt.Errorf("recipient %q: %w", r, err)
			}
			recipients = append(recipients, pub)
		}
		return recipients, "flags", nil
	}

	recipients, err := repoRecipients()
	if err != nil {
		if strings.Contains(err.Error(), "not inside a git repository") {
			return nil, "", nil
		}
		return nil, "", err
	}
	return recipients, ".tvault-recipients", nil
}

// selectSecretKeys narrows all to the requested keys, erroring on a miss.
func selectSecretKeys(all map[string]string, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return all, nil
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		v, ok := all[k]
		if !ok {
			return nil, fmt.Errorf("secret %q not found", k)
		}
		out[k] = v
	}
	return out, nil
}
