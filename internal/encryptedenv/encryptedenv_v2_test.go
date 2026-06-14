package encryptedenv

import (
	"bytes"
	"errors"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

func mustIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

func TestEncryptV2RoundTrip(t *testing.T) {
	id := mustIdentity(t)
	plaintext := []byte("DATABASE_URL=postgres://x\nSTRIPE_KEY=sk_test_abc\n")

	file, err := EncryptV2([][]byte{id.Recipient()}, plaintext)
	if err != nil {
		t.Fatalf("EncryptV2: %v", err)
	}
	if !bytes.HasPrefix(file, []byte(magicValue)) {
		t.Error("v2 output missing magic header")
	}
	if file[magicLen] != version2 {
		t.Errorf("version byte = %d, want %d", file[magicLen], version2)
	}
	// The plaintext must not appear anywhere in the encrypted file.
	if bytes.Contains(file, []byte("sk_test_abc")) {
		t.Error("plaintext leaked into encrypted v2 file")
	}

	got, err := DecryptV2(id, file)
	if err != nil {
		t.Fatalf("DecryptV2: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %q", got)
	}
}

func TestEncryptV2MultiRecipient(t *testing.T) {
	alice, bob, carol := mustIdentity(t), mustIdentity(t), mustIdentity(t)
	plaintext := []byte("TOKEN=shared\n")

	file, err := EncryptV2([][]byte{alice.Recipient(), bob.Recipient()}, plaintext)
	if err != nil {
		t.Fatalf("EncryptV2: %v", err)
	}

	// Both intended recipients can decrypt independently.
	for name, id := range map[string]*crypto.Identity{"alice": alice, "bob": bob} {
		got, derr := DecryptV2(id, file)
		if derr != nil {
			t.Fatalf("%s DecryptV2: %v", name, derr)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("%s got %q", name, got)
		}
	}

	// A third party who was not a recipient cannot.
	if _, err := DecryptV2(carol, file); !errors.Is(err, crypto.ErrNoMatchingRecipient) {
		t.Errorf("non-recipient decrypt should fail with ErrNoMatchingRecipient, got %v", err)
	}
}

func TestEncryptV2WrongIdentityFails(t *testing.T) {
	id := mustIdentity(t)
	other := mustIdentity(t)
	file, err := EncryptV2([][]byte{id.Recipient()}, []byte("SECRET=x\n"))
	if err != nil {
		t.Fatalf("EncryptV2: %v", err)
	}
	if _, err := DecryptV2(other, file); !errors.Is(err, crypto.ErrNoMatchingRecipient) {
		t.Errorf("wrong identity should fail, got %v", err)
	}
}

func TestEncryptV2NoRecipients(t *testing.T) {
	if _, err := EncryptV2(nil, []byte("x")); err == nil {
		t.Error("EncryptV2 with no recipients should error")
	}
}

// TestV2IsKEKIndependent is the core property: a v2 file is decryptable with
// only the identity — no vault, no KEK, no passphrase ever touches it.
func TestV2IsKEKIndependent(t *testing.T) {
	id := mustIdentity(t)
	plaintext := []byte("API_KEY=independent\n")
	file, err := EncryptV2([][]byte{id.Recipient()}, plaintext)
	if err != nil {
		t.Fatalf("EncryptV2: %v", err)
	}
	// Decrypting with a (wrong) KEK path must reject this file outright —
	// it is not a v1 file and must never be openable by the passphrase path.
	kek := makeKEK(t)
	if _, err := Decrypt(kek, file); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("v1 Decrypt of a v2 file should report unsupported version, got %v", err)
	}
	// And the identity alone opens it.
	if _, err := DecryptV2(id, file); err != nil {
		t.Errorf("identity-only decrypt failed: %v", err)
	}
}

func TestFileVersionDetection(t *testing.T) {
	id := mustIdentity(t)
	kek := makeKEK(t)

	v1, err := Encrypt(kek, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	v2, err := EncryptV2([][]byte{id.Recipient()}, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}

	if got, _ := FileVersion(v1); got != version {
		t.Errorf("v1 file version = %d, want %d", got, version)
	}
	if got, _ := FileVersion(v2); got != version2 {
		t.Errorf("v2 file version = %d, want %d", got, version2)
	}
	if _, err := FileVersion([]byte("not-a-vault-file")); !errors.Is(err, ErrInvalidMagic) {
		t.Errorf("bad magic should fail, got %v", err)
	}
	if _, err := FileVersion(nil); !errors.Is(err, ErrInvalidMagic) {
		t.Errorf("empty input should fail, got %v", err)
	}
}

func TestDecryptV2RejectsV1File(t *testing.T) {
	id := mustIdentity(t)
	kek := makeKEK(t)
	v1, err := Encrypt(kek, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptV2(id, v1); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("DecryptV2 of a v1 file should report unsupported version, got %v", err)
	}
}

func TestDecryptV2RejectsTruncated(t *testing.T) {
	id := mustIdentity(t)
	file, err := EncryptV2([][]byte{id.Recipient()}, []byte("SECRET=x\n"))
	if err != nil {
		t.Fatal(err)
	}

	// Truncate inside the recipient block (after the count, before stanzas).
	short := file[:v2PrefixLen+2]
	if _, err := DecryptV2(id, short); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated recipient block should be ErrMalformed, got %v", err)
	}

	// Truncate the count header itself.
	tooShort := file[:v2PrefixLen+1]
	if _, err := DecryptV2(id, tooShort); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated count header should be ErrMalformed, got %v", err)
	}
}

func TestDecryptV2DetectsTamperedBody(t *testing.T) {
	id := mustIdentity(t)
	file, err := EncryptV2([][]byte{id.Recipient()}, []byte("SECRET=x\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip the last byte of the AEAD-protected body.
	tampered := bytes.Clone(file)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := DecryptV2(id, tampered); err == nil {
		t.Error("tampered v2 body should fail to decrypt")
	}
}

func TestV2EmptyPlaintext(t *testing.T) {
	id := mustIdentity(t)
	file, err := EncryptV2([][]byte{id.Recipient()}, nil)
	if err != nil {
		t.Fatalf("EncryptV2 empty: %v", err)
	}
	got, err := DecryptV2(id, file)
	if err != nil {
		t.Fatalf("DecryptV2 empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %q", got)
	}
}
