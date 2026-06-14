package cmd

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

// Git clean/smudge filters give "commit-safe secrets" a transparent UX:
// files matched in .gitattributes are encrypted to a set of recipients on
// the way INTO the repo (clean) and decrypted on the way OUT to the working
// tree (smudge). The plaintext never enters git history; the working tree
// shows plaintext for anyone holding a recipient identity, and stays
// encrypted ("locked") for anyone who does not — exactly like git-crypt, but
// keyed by the X25519 recipient layer instead of a shared symmetric key.
//
// Recipients live in a committed .tvault-recipients file (one tvault1… per
// line) so the read-set travels with the repo. The local identity used to
// decrypt is taken from $TVAULT_IDENTITY, then `git config tvault.identity`,
// then "default", resolved under ~/.tvault/identities/<name>.key.
//
// Idempotency: a randomized AEAD would make every `git status` show the file
// as modified (re-encrypting the same plaintext yields different bytes). The
// clean filter avoids this by decrypting the already-staged blob and, when
// the plaintext is unchanged, re-emitting that blob verbatim. When no
// identity is available it falls back to a fresh encryption.

var gitFilterRecipients []string

var gitFilterCmd = &cobra.Command{
	Use:   "git-filter",
	Short: "Transparently encrypt tracked files on commit, decrypt on checkout",
	Long: `Configure git clean/smudge filters so matched files are stored
encrypted in the repository and appear as plaintext in your working tree.

This is the "commit your secrets safely" workflow: secrets are encrypted to
the X25519 recipients listed in .tvault-recipients (committed, public) and
decrypted locally with your identity. CI or an agent that holds a recipient
identity reads them transparently; anyone else sees only ciphertext.

Typical setup:
  tvault identity new                       # if you don't have one yet
  tvault git-filter install --recipient tvault1…   # you (and/or CI)
  tvault git-filter track .env 'secrets/*.env'      # what to encrypt
  git add .gitattributes .tvault-recipients && git commit -m "enable tvault"

Add a teammate later by appending their recipient to .tvault-recipients and
committing it; re-touch the files so they re-encrypt to the new set.`,
}

var gitFilterInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Register the tvault clean/smudge filters in this repository",
	Long: `Register filter.tvault.{clean,smudge,required} in this repo's git
config. Pass --recipient (repeatable) to seed .tvault-recipients.`,
	RunE: runGitFilterInstall,
}

var gitFilterTrackCmd = &cobra.Command{
	Use:   "track <pattern>...",
	Short: "Add .gitattributes patterns that should be encrypted",
	Long: `Append "<pattern> filter=tvault" entries to .gitattributes, the way
"git lfs track" works. Patterns already tracked are left untouched.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runGitFilterTrack,
}

var gitFilterStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show filter configuration, recipients, and identity availability",
	RunE:  runGitFilterStatus,
}

var gitFilterCheckoutCmd = &cobra.Command{
	Use:   "checkout",
	Short: "Re-decrypt tracked files in the working tree (run after cloning)",
	Long: `Force git to re-apply the smudge filter to tvault-tracked files that
are still encrypted in the working tree. Run this once after cloning a repo
(or after running install) so committed secrets appear as plaintext. Only
files that are currently ciphertext are touched, so local edits are never
clobbered; without an identity the files simply stay encrypted.`,
	RunE: runGitFilterCheckout,
}

var gitFilterUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the tvault clean/smudge filters from this repository",
	RunE:  runGitFilterUninstall,
}

// gitCleanCmd and gitSmudgeCmd are invoked by git, not by humans.
var gitCleanCmd = &cobra.Command{
	Use:    "git-clean [path]",
	Short:  "clean filter: read plaintext on stdin, write ciphertext to stdout",
	Args:   cobra.MaximumNArgs(1),
	Hidden: true,
	RunE:   runGitClean,
}

var gitSmudgeCmd = &cobra.Command{
	Use:    "git-smudge [path]",
	Short:  "smudge filter: read ciphertext on stdin, write plaintext to stdout",
	Args:   cobra.MaximumNArgs(1),
	Hidden: true,
	RunE:   runGitSmudge,
}

func init() {
	rootCmd.AddCommand(gitFilterCmd, gitCleanCmd, gitSmudgeCmd)
	gitFilterCmd.AddCommand(gitFilterInstallCmd, gitFilterTrackCmd, gitFilterStatusCmd, gitFilterCheckoutCmd, gitFilterUninstallCmd)
	gitFilterInstallCmd.Flags().StringArrayVar(&gitFilterRecipients, "recipient", nil,
		"Recipient (tvault1…) to seed into .tvault-recipients; repeatable")
}

// --- filter programs (invoked by git) -------------------------------------

func runGitClean(_ *cobra.Command, args []string) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	// Already encrypted (e.g. a locked working tree round-tripping): never
	// double-encrypt — pass it straight through.
	if v, verr := encryptedenv.FileVersion(data); verr == nil && (v == 1 || v == 2) {
		_, werr := os.Stdout.Write(data)
		return werr
	}

	recipients, err := repoRecipients()
	if err != nil {
		return err
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured: add tvault1… lines to .tvault-recipients " +
			"or run `tvault git-filter install --recipient <tvault1…>`")
	}

	// Idempotency: if the staged blob already decrypts to this exact
	// plaintext, re-emit it so git sees no change.
	if len(args) > 0 {
		if blob, ok := reuseStagedBlob(args[0], data); ok {
			_, werr := os.Stdout.Write(blob)
			return werr
		}
	}

	out, err := encryptedenv.EncryptV2(recipients, data)
	if err != nil {
		return err
	}
	_, werr := os.Stdout.Write(out)
	return werr
}

func runGitSmudge(_ *cobra.Command, _ []string) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	v, verr := encryptedenv.FileVersion(data)
	if verr != nil || v != 2 {
		// Not a v2 file (plaintext already, or a v1 passphrase file the
		// filter can't open): leave it as-is.
		_, werr := os.Stdout.Write(data)
		return werr
	}

	id, ierr := gitIdentity()
	if ierr != nil || id == nil {
		fmt.Fprintln(os.Stderr, "tvault: no identity available; leaving file encrypted "+
			"(create one with `tvault identity new`, or set `git config tvault.identity <name>`)")
		_, werr := os.Stdout.Write(data)
		return werr
	}
	pt, derr := encryptedenv.DecryptV2(id, data)
	if derr != nil {
		fmt.Fprintf(os.Stderr, "tvault: cannot decrypt (this identity is not a recipient?); "+
			"leaving file encrypted: %v\n", derr)
		_, werr := os.Stdout.Write(data)
		return werr
	}
	_, werr := os.Stdout.Write(pt)
	return werr
}

// reuseStagedBlob returns the currently-staged encrypted blob for path when
// it decrypts to plaintext, so re-cleaning an unchanged file is a no-op.
func reuseStagedBlob(path string, plaintext []byte) ([]byte, bool) {
	id, err := gitIdentity()
	if err != nil || id == nil {
		return nil, false
	}
	blob, err := gitOutput("", "cat-file", "blob", ":"+path)
	if err != nil || len(blob) == 0 {
		return nil, false
	}
	if v, verr := encryptedenv.FileVersion(blob); verr != nil || v != 2 {
		return nil, false
	}
	dec, err := encryptedenv.DecryptV2(id, blob)
	if err != nil {
		return nil, false
	}
	if !bytes.Equal(dec, plaintext) {
		return nil, false
	}
	return blob, true
}

// --- management commands ---------------------------------------------------

func runGitFilterInstall(_ *cobra.Command, _ []string) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	cfg := [][2]string{
		{"filter.tvault.clean", "tvault git-clean %f"},
		{"filter.tvault.smudge", "tvault git-smudge %f"},
		{"filter.tvault.required", "true"},
	}
	for _, kv := range cfg {
		if _, cerr := gitOutput(root, "config", kv[0], kv[1]); cerr != nil {
			return fmt.Errorf("set %s: %w", kv[0], cerr)
		}
	}

	added := 0
	if len(gitFilterRecipients) > 0 {
		added, err = appendRecipients(root, gitFilterRecipients)
		if err != nil {
			return err
		}
	}

	// If this repo already has committed, still-encrypted tracked files
	// (e.g. a fresh clone), decrypt them into the working tree now. A
	// failure here doesn't undo the install, so warn rather than abort.
	decrypted, rerr := resmudgeTracked(root)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not refresh working tree: %v\n", rerr)
	}

	if jsonOutput {
		return writeJSON(map[string]any{"installed": true, "recipients_added": added, "decrypted": decrypted})
	}
	Success("Installed tvault clean/smudge filters in %s", root)
	if added > 0 {
		PrintKeyValue("Recipients added", fmt.Sprintf("%d → %s", added, filepath.Join(root, ".tvault-recipients")))
	}
	if decrypted > 0 {
		PrintKeyValue("Decrypted", fmt.Sprintf("%d tracked file(s) into the working tree", decrypted))
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Next:")
	fmt.Fprintln(os.Stderr, "  tvault git-filter track .env        # choose what to encrypt")
	fmt.Fprintln(os.Stderr, "  git add .gitattributes .tvault-recipients && git commit -m \"enable tvault\"")
	return nil
}

func runGitFilterCheckout(_ *cobra.Command, _ []string) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	n, err := resmudgeTracked(root)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(map[string]any{"decrypted": n})
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "No encrypted tracked files to decrypt (already plaintext, or no identity).")
		return nil
	}
	Success("Re-decrypted %d tracked file(s) in the working tree", n)
	return nil
}

// resmudgeTracked forces git to re-apply the smudge filter to every
// tvault-tracked file that is currently ciphertext in the working tree.
// Files already in plaintext are skipped (so local edits survive), and an
// undecryptable file is left encrypted by the smudge filter itself. Returns
// the count that changed from ciphertext to plaintext.
func resmudgeTracked(root string) (int, error) {
	out, err := gitOutput(root, "ls-files", "-z")
	if err != nil {
		return 0, err
	}
	files := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	n := 0
	for _, f := range files {
		if f == "" {
			continue
		}
		attr, aerr := gitOutput(root, "check-attr", "filter", "--", f)
		if aerr != nil || !strings.Contains(string(attr), "filter: tvault") {
			continue
		}
		full := filepath.Join(root, f)
		data, rerr := os.ReadFile(full)
		if rerr != nil {
			continue
		}
		if v, verr := encryptedenv.FileVersion(data); verr != nil || v != 2 {
			continue // already plaintext (or not ours) — leave it alone
		}
		if rmErr := os.Remove(full); rmErr != nil {
			return n, rmErr
		}
		if _, coErr := gitOutput(root, "checkout", "HEAD", "--", f); coErr != nil {
			return n, coErr
		}
		// Count only if it actually became plaintext (identity present).
		if after, aerr := os.ReadFile(full); aerr == nil {
			if v, verr := encryptedenv.FileVersion(after); verr != nil || v != 2 {
				n++
			}
		}
	}
	return n, nil
}

func runGitFilterTrack(_ *cobra.Command, args []string) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	path := filepath.Join(root, ".gitattributes")
	existing := map[string]bool{}
	if data, rerr := os.ReadFile(path); rerr == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				existing[f[0]] = true
			}
		}
	} else if !os.IsNotExist(rerr) {
		return rerr
	}

	var toAdd []string
	for _, p := range args {
		if !existing[p] {
			toAdd = append(toAdd, p)
		}
	}
	if len(toAdd) > 0 {
		// .gitattributes is a public, committed config file; 0644 is intended.
		f, oerr := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // public commit-intended file
		if oerr != nil {
			return oerr
		}
		w := bufio.NewWriter(f)
		for _, p := range toAdd {
			fmt.Fprintf(w, "%s filter=tvault\n", p)
		}
		if err := w.Flush(); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}

	if jsonOutput {
		return writeJSON(map[string]any{"tracked": args, "added": toAdd})
	}
	if len(toAdd) == 0 {
		fmt.Fprintln(os.Stderr, "All patterns already tracked.")
		return nil
	}
	Success("Tracking %d pattern(s) in .gitattributes", len(toAdd))
	for _, p := range toAdd {
		fmt.Fprintf(os.Stderr, "  %s filter=tvault\n", p)
	}
	return nil
}

func runGitFilterStatus(_ *cobra.Command, _ []string) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	cleanCfg, cerr := gitOutput(root, "config", "--get", "filter.tvault.clean")
	installed := cerr == nil && strings.TrimSpace(string(cleanCfg)) != ""

	recipients, rerr := repoRecipients()
	idName := identityName()
	idPath := filepath.Join(identitiesDir(), idName+".key")
	_, idStatErr := os.Stat(idPath)
	idAvailable := idStatErr == nil

	patterns := trackedPatterns(root)

	if jsonOutput {
		recs := make([]string, 0, len(recipients))
		for _, r := range recipients {
			recs = append(recs, crypto.EncodeRecipient(r))
		}
		return writeJSON(map[string]any{
			"installed":          installed,
			"recipients":         recs,
			"identity":           idName,
			"identity_available": idAvailable,
			"tracked":            patterns,
		})
	}

	if installed {
		Success("Filters installed in %s", root)
	} else {
		fmt.Fprintln(os.Stderr, "Filters NOT installed (run: tvault git-filter install)")
	}
	PrintKeyValue("Recipients", recipientSummary(recipients, rerr))
	avail := "missing — files will stay encrypted"
	if idAvailable {
		avail = "available"
	}
	PrintKeyValue("Identity", fmt.Sprintf("%s (%s)", idName, avail))
	if len(patterns) == 0 {
		PrintKeyValue("Tracked", "(none — run: tvault git-filter track <pattern>)")
	} else {
		PrintKeyValue("Tracked", strings.Join(patterns, ", "))
	}
	return nil
}

func runGitFilterUninstall(_ *cobra.Command, _ []string) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	// Remove the whole [filter "tvault"] section. A repo that was never
	// installed has no such section, which is not an error here.
	if _, derr := gitOutput(root, "config", "--remove-section", "filter.tvault"); derr != nil &&
		!strings.Contains(derr.Error(), "No such section") {
		return fmt.Errorf("remove filter section: %w", derr)
	}
	if jsonOutput {
		return writeJSON(map[string]any{"uninstalled": true})
	}
	Success("Removed tvault filters from %s", root)
	fmt.Fprintln(os.Stderr, "Note: .gitattributes entries and .tvault-recipients were left in place.")
	return nil
}

// --- helpers ---------------------------------------------------------------

func gitOutput(dir string, args ...string) ([]byte, error) {
	c := exec.CommandContext(context.Background(), "git", args...)
	if dir != "" {
		c.Dir = dir
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func repoRoot() (string, error) {
	out, err := gitOutput("", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("not inside a git repository")
	}
	return strings.TrimSpace(string(out)), nil
}

func repoRecipients() ([][]byte, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(root, ".tvault-recipients"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var recipients [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, derr := crypto.DecodeRecipient(line)
		if derr != nil {
			return nil, fmt.Errorf(".tvault-recipients: %w", derr)
		}
		recipients = append(recipients, pub)
	}
	return recipients, sc.Err()
}

// appendRecipients adds new recipients to .tvault-recipients, skipping
// duplicates and validating each. Returns how many were added.
func appendRecipients(root string, recipients []string) (int, error) {
	path := filepath.Join(root, ".tvault-recipients")
	have := map[string]bool{}
	hadContent := false
	if data, rerr := os.ReadFile(path); rerr == nil {
		hadContent = len(data) > 0
		for _, line := range strings.Split(string(data), "\n") {
			if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
				have[s] = true
			}
		}
	} else if !os.IsNotExist(rerr) {
		return 0, rerr
	}

	var toAdd []string
	for _, r := range recipients {
		r = strings.TrimSpace(r)
		if _, derr := crypto.DecodeRecipient(r); derr != nil {
			return 0, fmt.Errorf("recipient %q: %w", r, derr)
		}
		if !have[r] {
			toAdd = append(toAdd, r)
			have[r] = true
		}
	}
	if len(toAdd) == 0 {
		return 0, nil
	}

	// .tvault-recipients holds only public keys and is meant to be committed.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // public commit-intended file
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriter(f)
	if !hadContent {
		fmt.Fprintln(w, "# tvault recipients — public X25519 keys allowed to decrypt tracked files.")
		fmt.Fprintln(w, "# Safe to commit. Add a teammate by appending their `tvault identity` recipient.")
	}
	for _, r := range toAdd {
		fmt.Fprintln(w, r)
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	return len(toAdd), nil
}

// identityName resolves the identity name used by the smudge/clean filters.
func identityName() string {
	if name := strings.TrimSpace(os.Getenv("TVAULT_IDENTITY")); name != "" {
		return name
	}
	if out, err := gitOutput("", "config", "--get", "tvault.identity"); err == nil {
		if name := strings.TrimSpace(string(out)); name != "" {
			return name
		}
	}
	return "default"
}

// gitIdentity loads the identity used by the smudge/clean filters: the named
// key file, else TVAULT_IDENTITY_KEY (so a CI checkout with the key in its
// environment decrypts transparently). Returns (nil, nil) when neither exists
// — the "locked" state, where files stay encrypted rather than erroring.
func gitIdentity() (*crypto.Identity, error) {
	id, _, err := resolveIdentity(identityName())
	return id, err
}

func trackedPatterns(root string) []string {
	data, err := os.ReadFile(filepath.Join(root, ".gitattributes"))
	if err != nil {
		return nil
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "filter=tvault") {
			if f := strings.Fields(line); len(f) > 0 {
				patterns = append(patterns, f[0])
			}
		}
	}
	sort.Strings(patterns)
	return patterns
}

func recipientSummary(recipients [][]byte, err error) string {
	if err != nil {
		return "(error: " + err.Error() + ")"
	}
	if len(recipients) == 0 {
		return "(none — add to .tvault-recipients)"
	}
	short := make([]string, 0, len(recipients))
	for _, r := range recipients {
		enc := crypto.EncodeRecipient(r)
		if len(enc) > 20 {
			enc = enc[:20] + "…"
		}
		short = append(short, enc)
	}
	return fmt.Sprintf("%d (%s)", len(recipients), strings.Join(short, ", "))
}
