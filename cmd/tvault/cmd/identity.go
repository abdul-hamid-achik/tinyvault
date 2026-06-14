package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

// identities live alongside the vault but are independent of it: they are
// X25519 keypairs used by the recipient layer (sharing / committable
// secrets), not derived from the vault passphrase. Generating one needs
// neither an initialized nor an unlocked vault.

var identityNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage X25519 identities for sharing secrets",
	Long: `Manage the X25519 identities used by the recipient layer.

An identity is a keypair. Its PUBLIC half — the recipient string
(tvault1…) — is safe to share and commit; anything encrypted to it can
only be opened by the matching PRIVATE half, stored 0600 under
~/.tvault/identities/<name>.key. This is what lets you (eventually) share
or commit secrets without handing over the master passphrase.`,
}

var identityNewCmd = &cobra.Command{
	Use:   "new [name]",
	Short: "Generate a new identity (keypair) and print its recipient",
	Long: `Generate a new X25519 identity. The private key is written to
~/.tvault/identities/<name>.key (0600); the public recipient string is
printed for you to share. Default name is "default".

Examples:
  tvault identity new
  tvault identity new ci`,
	Args: cobra.MaximumNArgs(1),
	RunE: runIdentityNew,
}

var identityListCmd = &cobra.Command{
	Use:   "list",
	Short: "List local identities and their recipient strings",
	RunE:  runIdentityList,
}

func init() {
	rootCmd.AddCommand(identityCmd)
	identityCmd.AddCommand(identityNewCmd, identityListCmd)
}

func identitiesDir() string { return filepath.Join(getVaultDir(), "identities") }

func runIdentityNew(_ *cobra.Command, args []string) error {
	name := "default"
	if len(args) == 1 {
		name = args[0]
	}
	if !identityNameRE.MatchString(name) {
		return fmt.Errorf("invalid identity name %q (use letters, digits, '-', '_')", name)
	}

	dir := identitiesDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create identities dir: %w", err)
	}
	path := filepath.Join(dir, name+".key")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("identity %q already exists at %s", name, path)
	}

	id, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	recipient := crypto.EncodeRecipient(id.Recipient())
	content := fmt.Sprintf("# tvault identity %q — KEEP SECRET, never commit or share this file\n# recipient: %s\n%s\n",
		name, recipient, crypto.EncodeIdentity(id))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}

	if jsonOutput {
		return writeJSON(map[string]string{"name": name, "recipient": recipient, "path": path})
	}
	Success("Created identity %q", name)
	PrintKeyValue("Private key", path+" (0600 — do not commit)")
	PrintKeyValue("Recipient", recipient)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Share the recipient string; keep the .key file secret.")
	return nil
}

func runIdentityList(_ *cobra.Command, _ []string) error {
	dir := identitiesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if jsonOutput {
				return writeJSON([]any{})
			}
			fmt.Fprintln(os.Stderr, "No identities yet. Create one with: tvault identity new")
			return nil
		}
		return err
	}

	type ident struct {
		Name      string `json:"name"`
		Recipient string `json:"recipient"`
	}
	var idents []ident
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".key")
		id, lerr := loadIdentity(filepath.Join(dir, e.Name()))
		if lerr != nil {
			idents = append(idents, ident{Name: name, Recipient: "(unreadable: " + lerr.Error() + ")"})
			continue
		}
		idents = append(idents, ident{Name: name, Recipient: crypto.EncodeRecipient(id.Recipient())})
	}
	sort.Slice(idents, func(i, j int) bool { return idents[i].Name < idents[j].Name })

	if jsonOutput {
		return writeJSON(idents)
	}
	if len(idents) == 0 {
		fmt.Fprintln(os.Stderr, "No identities yet. Create one with: tvault identity new")
		return nil
	}
	for _, id := range idents {
		fmt.Printf("%-16s %s\n", id.Name, id.Recipient)
	}
	return nil
}

// loadIdentity reads an identity key file, skipping comment/blank lines.
func loadIdentity(path string) (*crypto.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return crypto.DecodeIdentity(line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no identity key found in %s", path)
}
