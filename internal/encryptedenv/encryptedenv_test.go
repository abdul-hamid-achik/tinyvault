package encryptedenv

import (
	"bytes"
	"errors"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

func makeKEK(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kek := makeKEK(t)
	plaintext := []byte("DATABASE_URL=postgres://x\nSTRIPE_KEY=sk_test_abc\n")

	ct, err := Encrypt(kek, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The output must start with the magic header.
	if !bytes.HasPrefix(ct, []byte(magicValue)) {
		t.Errorf("missing magic header; got %q", ct[:16])
	}
	if len(ct) <= headerLen {
		t.Errorf("ciphertext shorter than header: %d <= %d", len(ct), headerLen)
	}

	pt, err := Decrypt(kek, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip mismatch:\n got: %q\nwant: %q", pt, plaintext)
	}
}

func TestDecryptRejectsBadMagic(t *testing.T) {
	kek := makeKEK(t)
	bogus := []byte("not-tvault-encrypted\x00\x01\x00\x00\x00")
	bogus = append(bogus, make([]byte, 28)...) // pad to header length
	bogus = append(bogus, []byte("junk")...)
	if _, err := Decrypt(kek, bogus); !errors.Is(err, ErrInvalidMagic) {
		t.Errorf("expected ErrInvalidMagic, got %v", err)
	}
}

func TestDecryptRejectsShortInput(t *testing.T) {
	kek := makeKEK(t)
	if _, err := Decrypt(kek, []byte("tiny")); !errors.Is(err, ErrInvalidMagic) {
		t.Errorf("expected ErrInvalidMagic for short input, got %v", err)
	}
}

func TestDecryptFailsOnTamperedCiphertext(t *testing.T) {
	kek := makeKEK(t)
	plaintext := []byte("SECRET=hunter2\n")

	ct, err := Encrypt(kek, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte deep in the ciphertext.
	ct[len(ct)-1] ^= 0xFF

	if _, err := Decrypt(kek, ct); err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext")
	}
}

func TestEncryptRejectsInvalidKEK(t *testing.T) {
	bad := []byte("too-short")
	if _, err := Encrypt(bad, []byte("x")); !errors.Is(err, crypto.ErrInvalidKeySize) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestDifferentFilesUseDifferentSalts(t *testing.T) {
	kek := makeKEK(t)
	plaintext := []byte("A=1\n")

	ct1, err := Encrypt(kek, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := Encrypt(kek, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Salts at offset magicLen+4..magicLen+4+SaltSize
	saltOffset := len(magicValue) + 4
	if bytes.Equal(ct1[saltOffset:saltOffset+crypto.SaltSize], ct2[saltOffset:saltOffset+crypto.SaltSize]) {
		t.Error("two encrypts of the same content produced identical salts (not random)")
	}

	// Nonces too.
	nonceOffset := saltOffset + crypto.SaltSize
	if bytes.Equal(ct1[nonceOffset:nonceOffset+crypto.NonceSize], ct2[nonceOffset:nonceOffset+crypto.NonceSize]) {
		t.Error("two encrypts of the same content produced identical nonces (not random)")
	}
}

func TestWrongKEKFails(t *testing.T) {
	kek1 := makeKEK(t)
	kek2 := makeKEK(t)
	ct, err := Encrypt(kek1, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(kek2, ct); err == nil {
		t.Fatal("expected decryption to fail with a different KEK")
	}
}
