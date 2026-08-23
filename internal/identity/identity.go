// Package identity manages the X25519 identity key files used by the recipient
// layer (sharing / committable secrets). Identities live beside the vault but
// are independent of it: they are keypairs, not derived from the vault
// passphrase. This package is the single source of truth for the on-disk
// layout, naming, and write format so the CLI and the MCP server stay
// consistent (an identity created by one must be readable by the other).
package identity

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

// nameRE constrains identity names so a caller-supplied value can never
// traverse outside the identities directory (e.g. "../../etc/x").
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidName reports whether name is a legal identity name.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Dir returns the identities directory inside the given vault directory.
func Dir(vaultDir string) string { return filepath.Join(vaultDir, "identities") }

// File returns the key-file path for name (defaulting to "default"),
// erroring on an invalid name.
func File(vaultDir, name string) (string, error) {
	if name == "" {
		name = "default"
	}
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("invalid identity name %q (use letters, digits, '-', '_')", name)
	}
	return filepath.Join(Dir(vaultDir), name+".key"), nil
}

// Entry is a public listing of an identity: its name and recipient string.
// It never carries the private key.
type Entry struct {
	Name      string `json:"name"`
	Recipient string `json:"recipient"`
}

// New generates a new identity, writes the private key 0600 under the vault's
// identities directory, and returns the public recipient string and file path.
// It errors if an identity with that name already exists. The private key is
// never returned.
func New(vaultDir, name string) (recipient, path string, err error) {
	// Unlike File (which defaults an empty name to "default" for the decrypt
	// path), creation requires an explicit, valid name — an empty name is an
	// error. Callers that want the default pass "default" themselves.
	if !nameRE.MatchString(name) {
		return "", "", fmt.Errorf("invalid identity name %q (use letters, digits, '-', '_')", name)
	}
	dir := Dir(vaultDir)
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return "", "", fmt.Errorf("create identities dir: %w", mkErr)
	}
	path = filepath.Join(dir, name+".key")
	if _, statErr := os.Stat(path); statErr == nil {
		return "", "", fmt.Errorf("identity %q already exists at %s", name, path)
	}

	id, genErr := crypto.GenerateIdentity()
	if genErr != nil {
		return "", "", genErr
	}
	recipient = crypto.EncodeRecipient(id.Recipient())
	content := fmt.Sprintf(
		"# tvault identity %q — KEEP SECRET, never commit or share this file\n# recipient: %s\n%s\n",
		name, recipient, crypto.EncodeIdentity(id))
	if wErr := os.WriteFile(path, []byte(content), 0o600); wErr != nil {
		return "", "", fmt.Errorf("write identity: %w", wErr)
	}
	return recipient, path, nil
}

// Load reads an identity key file, skipping comment/blank lines and decoding
// the first key line. It does not warn about file permissions; callers that
// care (the CLI) wrap this.
func Load(path string) (*crypto.Identity, error) {
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

// List returns all identities in the vault's identities directory (sorted by
// name) with their public recipient strings. A missing directory yields an
// empty slice. An unreadable key file is reported with a placeholder recipient
// rather than failing the whole listing.
func List(vaultDir string) ([]Entry, error) {
	dir := Dir(vaultDir)
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil
		}
		return nil, err
	}
	out := make([]Entry, 0, len(dirEntries))
	for _, e := range dirEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".key")
		id, lErr := Load(filepath.Join(dir, e.Name()))
		if lErr != nil {
			out = append(out, Entry{Name: name, Recipient: "(unreadable: " + lErr.Error() + ")"})
			continue
		}
		out = append(out, Entry{Name: name, Recipient: crypto.EncodeRecipient(id.Recipient())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// EnvKey is the environment variable that carries a private identity
// (a tvault-key1… string) so CI, ssh, and agents can decrypt without a
// key file or passphrase.
const EnvKey = "TVAULT_IDENTITY_KEY"

// Resolve returns the identity to decrypt with, plus a source tag
// ("file" | "env-key") for warnings and audit. Precedence:
//
//  1. The named key file (empty name → "default") if it exists on disk —
//     local dev stays deterministic.
//  2. Else the TVAULT_IDENTITY_KEY environment value — the CI / ssh / agent path.
//  3. Else (nil, "", nil): locked. The caller decides whether that is fatal.
//
// A malformed name is the only hard error (traversal safety via ValidName).
// A malformed env key errors without echoing the value.
func Resolve(vaultDir, name string) (*crypto.Identity, string, error) {
	keyPath, err := File(vaultDir, name)
	if err != nil {
		return nil, "", err
	}
	if _, statErr := os.Stat(keyPath); statErr == nil {
		id, lerr := Load(keyPath)
		if lerr != nil {
			return nil, "", lerr
		}
		return id, "file", nil
	}
	id, eerr := DecodeEnvKey()
	if eerr != nil {
		return nil, "", eerr
	}
	if id != nil {
		return id, "env-key", nil
	}
	return nil, "", nil
}

// DecodeEnvKey decodes TVAULT_IDENTITY_KEY, or returns (nil, nil) if unset.
// On decode failure the error never includes the key value.
func DecodeEnvKey() (*crypto.Identity, error) {
	v := strings.TrimSpace(os.Getenv(EnvKey))
	if v == "" {
		return nil, nil
	}
	id, err := crypto.DecodeIdentity(v)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", EnvKey, err)
	}
	return id, nil
}
