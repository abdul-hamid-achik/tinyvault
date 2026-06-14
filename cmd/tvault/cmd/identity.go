package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

// envIdentityKey is the environment variable that carries a private identity
// (a tvault-key1… string) directly, so CI runners, ssh targets, and agents can
// supply a per-context identity with no key file on disk and no passphrase.
const envIdentityKey = "TVAULT_IDENTITY_KEY"

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

var identityExportForce bool

var identityExportCmd = &cobra.Command{
	Use:   "export [name]",
	Short: "Print an identity's PRIVATE key for a secret store (CI/ssh)",
	Long: `Print the private key (tvault-key1…) for an identity so it can be
injected into a CI secret store or another machine as the TVAULT_IDENTITY_KEY
environment variable. The holder can then decrypt recipient-sealed secrets
with no passphrase and no key file.

This prints a SECRET. The key goes to stdout only (so it pipes cleanly); all
warnings go to stderr. To avoid accidentally dumping it into a terminal or a
log, it refuses to write to a non-terminal unless --force is given.

Examples:
  tvault identity export ci --force | gh secret set TVAULT_IDENTITY_KEY
  tvault identity export ci --json --force   # {name, recipient, private}`,
	Args: cobra.MaximumNArgs(1),
	RunE: runIdentityExport,
}

func init() {
	rootCmd.AddCommand(identityCmd)
	identityCmd.AddCommand(identityNewCmd, identityListCmd, identityExportCmd)
	identityExportCmd.Flags().BoolVar(&identityExportForce, "force", false,
		"Allow printing the private key to a non-terminal (e.g. a pipe)")
}

func identitiesDir() string { return filepath.Join(getVaultDir(), "identities") }

// resolveIdentityFile validates an identity name and returns the path to its
// key file. The name is constrained to identityNameRE so a caller-supplied
// value (flag or environment) can never traverse outside the identities
// directory (e.g. "--identity ../../etc/x").
func resolveIdentityFile(name string) (string, error) {
	if name == "" {
		name = "default"
	}
	if !identityNameRE.MatchString(name) {
		return "", fmt.Errorf("invalid identity name %q (use letters, digits, '-', '_')", name)
	}
	return filepath.Join(identitiesDir(), name+".key"), nil
}

// resolveIdentity returns the identity to decrypt with, plus a source tag
// ("file" | "env-key") for warnings/audit. Precedence:
//
//  1. The named key file (name from --identity / $TVAULT_IDENTITY / git config /
//     "default") IF it exists on disk — keeps local dev deterministic.
//  2. else the TVAULT_IDENTITY_KEY environment value — the CI / ssh / agent path,
//     where no file exists.
//  3. else "locked": (nil, "", nil) with no error; the caller decides whether a
//     missing identity is fatal (open/decrypt-env) or benign (git filters).
//
// A malformed name is the only hard error (traversal safety via identityNameRE).
func resolveIdentity(name string) (*crypto.Identity, string, error) {
	keyPath, err := resolveIdentityFile(name)
	if err != nil {
		return nil, "", err
	}
	if _, statErr := os.Stat(keyPath); statErr == nil {
		id, lerr := loadIdentity(keyPath)
		if lerr != nil {
			return nil, "", lerr
		}
		return id, "file", nil
	}
	id, eerr := decodeEnvIdentityKey()
	if eerr != nil {
		return nil, "", eerr
	}
	if id != nil {
		return id, "env-key", nil
	}
	return nil, "", nil
}

// decodeEnvIdentityKey decodes the TVAULT_IDENTITY_KEY environment value into
// an identity, or returns (nil, nil) if it is unset. On a decode failure the
// error NEVER echoes the key value (DecodeIdentity is already sanitized, and
// the %w chain carries no copy of the input).
func decodeEnvIdentityKey() (*crypto.Identity, error) {
	v := strings.TrimSpace(os.Getenv(envIdentityKey))
	if v == "" {
		return nil, nil
	}
	id, err := crypto.DecodeIdentity(v)
	if err != nil {
		// Never echo the key value; DecodeIdentity's error does not include it.
		return nil, fmt.Errorf("invalid %s: %w", envIdentityKey, err)
	}
	return id, nil
}

// warnEnvKeyUsed prints a one-line stderr notice about which identity source
// was used, so a passphrase-free decrypt is never silent and a stray env key
// that was overridden by a local file is surfaced.
func warnEnvKeyUsed(w io.Writer, source, cmd string) {
	switch source {
	case "env-key":
		fmt.Fprintf(w, "tvault: using %s (passphrase-free identity) for %s\n", envIdentityKey, cmd)
	case "file":
		if strings.TrimSpace(os.Getenv(envIdentityKey)) != "" {
			fmt.Fprintf(w, "tvault: %s is set but a local identity file takes precedence for %s\n", envIdentityKey, cmd)
		}
	}
}

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

// loadIdentity reads an identity key file, skipping comment/blank lines. It
// warns (but does not fail) if the file is group/world-readable, since the
// private key inside is meant to be 0600.
func loadIdentity(path string) (*crypto.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, serr := f.Stat(); serr == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: identity file %s is group/world-readable (mode %#o); run: chmod 600 %s\n",
			path, info.Mode().Perm(), path)
	}
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

func runIdentityExport(_ *cobra.Command, args []string) error {
	name := "default"
	if len(args) == 1 {
		name = args[0]
	}
	// Refuse to print a private key to a non-terminal unless forced — this
	// stops it from silently landing in a captured log; the intended use
	// (piping to a secret manager) opts in with --force.
	if !identityExportForce && !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("refusing to print a private key to a non-terminal without --force\n"+
			"  (pipe to a secret manager, e.g.: tvault identity export %s --force | gh secret set %s)",
			name, envIdentityKey)
	}

	path, err := resolveIdentityFile(name)
	if err != nil {
		return err
	}
	id, err := loadIdentity(path)
	if err != nil {
		return fmt.Errorf("load identity %q: %w", name, err)
	}
	private := crypto.EncodeIdentity(id)
	recipient := crypto.EncodeRecipient(id.Recipient())

	fmt.Fprintf(os.Stderr,
		"WARNING: printing the PRIVATE key for identity %q. It will appear in shell history and any captured\n"+
			"output. Pipe ONLY to a trusted secret manager; never save to disk, email, or commit.\n"+
			"Tip: in an interactive shell, prefix with 'set +o history;'.\n", name)

	if jsonOutput {
		return writeJSON(map[string]string{"name": name, "recipient": recipient, "private": private})
	}
	fmt.Println(private)
	return nil
}
