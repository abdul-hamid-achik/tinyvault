package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

// sealedBlobFor returns a v2 blob sealed to id, decryptable only by it.
func sealedBlobFor(t *testing.T, id *crypto.Identity, body string) []byte {
	t.Helper()
	blob, err := encryptedenv.EncryptV2([][]byte{id.Recipient()}, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestDecryptEnvV2WithEnvKeyNoFlag(t *testing.T) {
	resetSealFlags(t)
	withVaultDir(t, t.TempDir()) // empty: no identity files
	id := mustGenIdentity(t)
	t.Setenv(envIdentityKey, crypto.EncodeIdentity(id))

	blob := sealedBlobFor(t, id, "DB=postgres://x\n")
	path := filepath.Join(t.TempDir(), "b.enc")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	oldIn, oldOut, oldIdent := envEncryptIn, envEncryptOut, envDecryptIdentity
	defer func() { envEncryptIn, envEncryptOut, envDecryptIdentity = oldIn, oldOut, oldIdent }()
	envEncryptIn, envEncryptOut, envDecryptIdentity = path, "", "" // no --identity

	var out []byte
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() {
			if err := runEnvDecrypt(nil, nil); err != nil {
				t.Fatalf("decrypt-env: %v", err)
			}
		})
	})
	if !strings.Contains(string(out), "DB=postgres://x") {
		t.Errorf("env-key decrypt failed: %q", out)
	}
	if !strings.Contains(string(stderr), envIdentityKey) {
		t.Errorf("expected an env-key usage notice on stderr, got %q", stderr)
	}
}

func TestDecryptEnvV2NoIdentityNoEnvKey(t *testing.T) {
	resetSealFlags(t)
	withVaultDir(t, t.TempDir())
	t.Setenv(envIdentityKey, "")
	id := mustGenIdentity(t)
	blob := sealedBlobFor(t, id, "A=1\n")
	path := filepath.Join(t.TempDir(), "b.enc")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	oldIn, oldOut, oldIdent := envEncryptIn, envEncryptOut, envDecryptIdentity
	defer func() { envEncryptIn, envEncryptOut, envDecryptIdentity = oldIn, oldOut, oldIdent }()
	envEncryptIn, envEncryptOut, envDecryptIdentity = path, "", ""

	err := runEnvDecrypt(nil, nil)
	if err == nil {
		t.Fatal("v2 decrypt with no identity and no env key must error")
	}
	if !strings.Contains(err.Error(), "--identity") || !strings.Contains(err.Error(), envIdentityKey) {
		t.Errorf("error should mention both --identity and %s, got %v", envIdentityKey, err)
	}
}

func TestOpenViaEnvKey(t *testing.T) {
	resetSealFlags(t)
	withVaultDir(t, t.TempDir())
	id := mustGenIdentity(t)
	t.Setenv(envIdentityKey, crypto.EncodeIdentity(id))

	blob := sealedBlobFor(t, id, "KEY=val\n")
	path := filepath.Join(t.TempDir(), "b.enc")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	openIn, openIdentity, openOut = path, "", ""

	out := captureStdout(t, func() {
		if err := runOpen(nil, nil); err != nil {
			t.Fatalf("open: %v", err)
		}
	})
	if !strings.Contains(string(out), "KEY=val") {
		t.Errorf("open via env key failed: %q", out)
	}
}

func TestGitSmudgeViaEnvKey(t *testing.T) {
	withVaultDir(t, t.TempDir()) // empty: no identity files on disk
	id := mustGenIdentity(t)
	t.Setenv(envIdentityKey, crypto.EncodeIdentity(id))

	blob := sealedBlobFor(t, id, "SECRET=via-env-smudge\n")
	// runGitSmudge -> gitIdentity -> resolveIdentity (env-key branch) -> DecryptV2.
	out := runFilter(t, runGitSmudge, blob, ".env")
	if !strings.Contains(string(out), "SECRET=via-env-smudge") {
		t.Errorf("smudge via env key did not decrypt: %q", out)
	}
}

func TestEnvKeyValueNeverLeaksStderrOnSuccess(t *testing.T) {
	resetSealFlags(t)
	withVaultDir(t, t.TempDir())
	id := mustGenIdentity(t)
	keyStr := crypto.EncodeIdentity(id)
	t.Setenv(envIdentityKey, keyStr)

	blob := sealedBlobFor(t, id, "A=1\n")
	path := filepath.Join(t.TempDir(), "b.enc")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut, oldIdent := envEncryptIn, envEncryptOut, envDecryptIdentity
	defer func() { envEncryptIn, envEncryptOut, envDecryptIdentity = oldIn, oldOut, oldIdent }()
	envEncryptIn, envEncryptOut, envDecryptIdentity = path, "", ""

	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			if err := runEnvDecrypt(nil, nil); err != nil {
				t.Fatalf("decrypt-env: %v", err)
			}
		})
	})
	if strings.Contains(string(stderr), keyStr) {
		t.Error("private key value leaked to stderr on success")
	}
	if body := strings.TrimPrefix(keyStr, "tvault-key1"); strings.Contains(string(stderr), body) {
		t.Error("private key body leaked to stderr on success")
	}
}

func TestDecryptEnvV2EnvKeyNotRecipient(t *testing.T) {
	resetSealFlags(t)
	withVaultDir(t, t.TempDir())
	envID := mustGenIdentity(t)
	sealID := mustGenIdentity(t)
	t.Setenv(envIdentityKey, crypto.EncodeIdentity(envID))

	blob := sealedBlobFor(t, sealID, "A=1\n") // sealed to a DIFFERENT identity
	path := filepath.Join(t.TempDir(), "b.enc")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut, oldIdent := envEncryptIn, envEncryptOut, envDecryptIdentity
	defer func() { envEncryptIn, envEncryptOut, envDecryptIdentity = oldIn, oldOut, oldIdent }()
	envEncryptIn, envEncryptOut, envDecryptIdentity = path, "", ""

	var err error
	stderr := captureStderr(t, func() { err = runEnvDecrypt(nil, nil) })
	if err == nil {
		t.Fatal("decrypt with a non-recipient identity should error")
	}
	if !strings.Contains(string(stderr), envIdentityKey) {
		t.Errorf("expected the env-key usage notice on stderr, got %q", stderr)
	}
	if !strings.Contains(string(stderr), "not a recipient") {
		t.Errorf("expected the not-a-recipient hint on stderr, got %q", stderr)
	}
}

func TestGitIdentityEnvKeyAndLocked(t *testing.T) {
	withVaultDir(t, t.TempDir())

	// Locked: no file, no env key.
	t.Setenv(envIdentityKey, "")
	if id, err := gitIdentity(); err != nil || id != nil {
		t.Fatalf("locked gitIdentity should be (nil,nil), got id=%v err=%v", id, err)
	}

	// Env key present → non-nil (CI checkout decrypts transparently).
	want := mustGenIdentity(t)
	t.Setenv(envIdentityKey, crypto.EncodeIdentity(want))
	id, err := gitIdentity()
	if err != nil || id == nil {
		t.Fatalf("gitIdentity with env key should resolve, got id=%v err=%v", id, err)
	}
	if !equalRecipients(id, want) {
		t.Error("gitIdentity resolved a different identity from the env key")
	}
}
