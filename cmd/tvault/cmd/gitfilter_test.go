package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

// gitFilterRepo sets up a temp git repo + vault home with a "default"
// identity, chdirs into the repo, and returns the repo root and the
// identity's recipient string. Skips if git is unavailable.
func gitFilterRepo(t *testing.T) (root, recipient string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	base := t.TempDir()
	withVaultDir(t, filepath.Join(base, "home"))

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idDir := identitiesDir()
	if err := os.MkdirAll(idDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(idDir, "default.key"),
		[]byte(crypto.EncodeIdentity(id)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	for _, args := range [][]string{
		{"init"}, {"config", "user.email", "t@t.com"}, {"config", "user.name", "t"},
	} {
		if out, gerr := exec.CommandContext(context.Background(), "git", args...).CombinedOutput(); gerr != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), gerr, out)
		}
	}
	return repo, crypto.EncodeRecipient(id.Recipient())
}

// runFilter drives a clean/smudge RunE with the given stdin and captures
// what it writes to stdout.
func runFilter(t *testing.T, fn func(c *cobra.Command, args []string) error, in []byte, args ...string) []byte {
	t.Helper()
	rIn, wIn, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = wIn.Write(in); _ = wIn.Close() }()
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = rIn, wOut
	ferr := fn(nil, args)
	_ = wOut.Close()
	os.Stdin, os.Stdout = oldIn, oldOut

	out, _ := io.ReadAll(rOut)
	_ = rOut.Close()
	_ = rIn.Close()
	if ferr != nil {
		t.Fatalf("filter returned error: %v", ferr)
	}
	return out
}

func TestGitFilterCleanSmudgeRoundTrip(t *testing.T) {
	_, rec := gitFilterRepo(t)
	if _, err := appendRecipients(".", []string{rec}); err != nil {
		t.Fatalf("appendRecipients: %v", err)
	}

	plain := []byte("DB=postgres://x\nKEY=sk_live_SECRET\n")

	ct := runFilter(t, runGitClean, plain, ".env")
	if v, err := encryptedenv.FileVersion(ct); err != nil || v != 2 {
		t.Fatalf("clean output not a v2 file: v=%d err=%v", v, err)
	}
	if bytes.Contains(ct, []byte("sk_live_SECRET")) {
		t.Fatal("plaintext leaked through clean filter")
	}

	got := runFilter(t, runGitSmudge, ct, ".env")
	if !bytes.Equal(got, plain) {
		t.Fatalf("smudge round-trip mismatch: got %q", got)
	}
}

func TestGitFilterCleanRefusesWithoutRecipients(t *testing.T) {
	gitFilterRepo(t)
	// No .tvault-recipients written → clean must error rather than emit
	// unencrypted (or unprotected) output.
	rIn, wIn, _ := os.Pipe()
	go func() { _, _ = wIn.Write([]byte("A=1\n")); _ = wIn.Close() }()
	rOut, wOut, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = rIn, wOut
	err := runGitClean(nil, []string{".env"})
	_ = wOut.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	_, _ = io.ReadAll(rOut)
	_ = rOut.Close()
	_ = rIn.Close()
	if err == nil {
		t.Fatal("clean with no recipients should error")
	}
}

func TestGitFilterCleanPassesThroughAlreadyEncrypted(t *testing.T) {
	_, rec := gitFilterRepo(t)
	if _, err := appendRecipients(".", []string{rec}); err != nil {
		t.Fatal(err)
	}
	pub, _ := crypto.DecodeRecipient(rec)
	already, err := encryptedenv.EncryptV2([][]byte{pub}, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Feeding ciphertext back through clean must not double-encrypt.
	out := runFilter(t, runGitClean, already, ".env")
	if !bytes.Equal(out, already) {
		t.Fatal("clean double-encrypted an already-encrypted file")
	}
}

func TestGitFilterSmudgeLockedWithoutIdentity(t *testing.T) {
	_, rec := gitFilterRepo(t)
	pub, _ := crypto.DecodeRecipient(rec)
	ct, err := encryptedenv.EncryptV2([][]byte{pub}, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Remove the identity → "locked": smudge must leave the file encrypted
	// (pass through) rather than failing the checkout.
	if rerr := os.Remove(filepath.Join(identitiesDir(), "default.key")); rerr != nil {
		t.Fatal(rerr)
	}
	out := runFilter(t, runGitSmudge, ct, ".env")
	if !bytes.Equal(out, ct) {
		t.Fatal("locked smudge should pass ciphertext through unchanged")
	}
}

func TestGitFilterSmudgePassesThroughPlaintext(t *testing.T) {
	gitFilterRepo(t)
	plain := []byte("not encrypted at all\n")
	out := runFilter(t, runGitSmudge, plain, ".env")
	if !bytes.Equal(out, plain) {
		t.Fatal("smudge mangled a non-tvault file")
	}
}

func TestAppendRecipientsDedupAndValidate(t *testing.T) {
	gitFilterRepo(t)
	a, _ := crypto.GenerateIdentity()
	b, _ := crypto.GenerateIdentity()
	ra, rb := crypto.EncodeRecipient(a.Recipient()), crypto.EncodeRecipient(b.Recipient())

	n, err := appendRecipients(".", []string{ra, rb, ra}) // ra duplicated
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 unique recipients added, got %d", n)
	}
	// Re-adding ra is a no-op.
	n2, err := appendRecipients(".", []string{ra})
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Errorf("re-adding existing recipient should add 0, got %d", n2)
	}
	// Garbage recipient is rejected.
	if _, err := appendRecipients(".", []string{"not-a-recipient"}); err == nil {
		t.Error("invalid recipient should be rejected")
	}

	recs, err := repoRecipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Errorf("repoRecipients should read back 2, got %d", len(recs))
	}
}

func TestReuseStagedBlobIdempotency(t *testing.T) {
	_, rec := gitFilterRepo(t)
	pub, _ := crypto.DecodeRecipient(rec)
	plain := []byte("KEY=value\n")
	ct, err := encryptedenv.EncryptV2([][]byte{pub}, plain)
	if err != nil {
		t.Fatal(err)
	}
	// Stage the encrypted blob as ".env" (no filter configured, so it is
	// stored verbatim) — this is the "currently committed" ciphertext.
	if werr := os.WriteFile(".env", ct, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if out, gerr := exec.CommandContext(context.Background(), "git", "add", ".env").CombinedOutput(); gerr != nil {
		t.Fatalf("git add: %v: %s", gerr, out)
	}

	// Unchanged plaintext → reuse the staged blob verbatim (no spurious diff).
	blob, ok := reuseStagedBlob(".env", plain)
	if !ok || !bytes.Equal(blob, ct) {
		t.Fatalf("reuseStagedBlob should return the staged blob for unchanged plaintext (ok=%v)", ok)
	}
	// Changed plaintext → no reuse (fresh encryption needed).
	if _, ok := reuseStagedBlob(".env", []byte("KEY=changed\n")); ok {
		t.Fatal("reuseStagedBlob should not reuse when plaintext changed")
	}
}
