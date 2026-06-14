package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

func writeTestIdentity(t *testing.T, name string, id *crypto.Identity) {
	t.Helper()
	dir := identitiesDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".key"),
		[]byte(crypto.EncodeIdentity(id)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// resetSealFlags restores the package-level seal/open flag vars after a test.
func resetSealFlags(t *testing.T) {
	t.Helper()
	r, k, so := sealRecipients, sealKeys, sealOut
	in, ident, oo := openIn, openIdentity, openOut
	t.Cleanup(func() {
		sealRecipients, sealKeys, sealOut = r, k, so
		openIn, openIdentity, openOut = in, ident, oo
	})
}

func TestSealOpenRoundTrip(t *testing.T) {
	resetSealFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "DB_URL", "postgres://x"); err != nil {
		t.Fatal(err)
	}
	// A multi-line PEM — the case naive "k=v" rendering would corrupt.
	pem := "-----BEGIN-----\nline1\nline2\n-----END-----"
	if err := v.SetSecret("default", "PEM", pem); err != nil {
		t.Fatal(err)
	}
	v.Close()

	id, _ := crypto.GenerateIdentity()
	writeTestIdentity(t, "default", id)
	sealRecipients = []string{crypto.EncodeRecipient(id.Recipient())}

	sealed := captureStdout(t, func() {
		if err := runSeal(nil, nil); err != nil {
			t.Fatalf("seal: %v", err)
		}
	})

	if ver, _ := encryptedenv.FileVersion(sealed); ver != 2 {
		t.Fatalf("sealed output is not v2: %d", ver)
	}
	if strings.Contains(string(sealed), "postgres://x") {
		t.Fatal("plaintext leaked into sealed output")
	}

	// Open it back via the CLI (drive through a file, not stdin).
	blob := filepath.Join(t.TempDir(), "blob.enc")
	if err := os.WriteFile(blob, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	openIn = blob
	openIdentity = "default"
	opened := captureStdout(t, func() {
		if err := runOpen(nil, nil); err != nil {
			t.Fatalf("open: %v", err)
		}
	})

	parsed, err := dotenv.ParseBytes(".env", opened)
	if err != nil {
		t.Fatalf("re-parse opened dotenv: %v\n%s", err, opened)
	}
	byKey := map[string]string{}
	for _, e := range parsed.Entries {
		byKey[e.Key] = e.Value
	}
	if byKey["DB_URL"] != "postgres://x" {
		t.Errorf("DB_URL round-trip: %q", byKey["DB_URL"])
	}
	if byKey["PEM"] != pem {
		t.Errorf("multi-line PEM corrupted: got %q want %q", byKey["PEM"], pem)
	}
}

// TestSealCrossCompatibleWithDecryptEnv proves the seal CLI emits the same v2
// format as encrypt-env --recipient: a sealed blob opens with DecryptV2.
func TestSealCrossCompatibleWithDecryptEnv(t *testing.T) {
	resetSealFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "TOKEN", "abc123"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	id, _ := crypto.GenerateIdentity()
	writeTestIdentity(t, "default", id)
	sealRecipients = []string{crypto.EncodeRecipient(id.Recipient())}
	sealKeys = []string{"TOKEN"}

	sealed := captureStdout(t, func() {
		if err := runSeal(nil, nil); err != nil {
			t.Fatalf("seal: %v", err)
		}
	})
	pt, err := encryptedenv.DecryptV2(id, sealed)
	if err != nil {
		t.Fatalf("DecryptV2 of seal output: %v", err)
	}
	if !strings.Contains(string(pt), "TOKEN=abc123") {
		t.Errorf("unexpected sealed body: %q", pt)
	}
	if strings.Contains(string(pt), "DB_URL") {
		t.Error("--key subset not honored")
	}
}

func TestOpenRejectsV1File(t *testing.T) {
	resetSealFlags(t)
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	writeTestIdentity(t, "default", mustGenIdentity(t))

	kek, _ := crypto.GenerateKey()
	v1, err := encryptedenv.Encrypt(kek, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(t.TempDir(), "v1.enc")
	if err := os.WriteFile(blob, v1, 0o600); err != nil {
		t.Fatal(err)
	}
	openIn = blob
	openIdentity = "default"
	err = runOpen(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "v2") {
		t.Fatalf("open should reject a v1 file with a v2 hint, got %v", err)
	}
}

func TestSealNoRecipientsErrors(t *testing.T) {
	resetSealFlags(t)
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	// chdir somewhere that is not a git repo so the .tvault-recipients
	// fallback finds nothing.
	t.Chdir(t.TempDir())
	sealRecipients = nil
	if err := runSeal(nil, nil); err == nil {
		t.Fatal("seal with no recipients and no .tvault-recipients should error")
	}
}

func mustGenIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
