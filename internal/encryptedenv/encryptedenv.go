// Package encryptedenv implements the .env.encrypted file format
// (magic: "tvault-encrypted-v1").
//
// The file is a self-contained, AES-256-GCM-encrypted dotenv payload
// tied to the vault's KEK. Decryption requires the vault to be unlocked.
// The format is intentionally simple: anyone holding the vault
// passphrase can decrypt; there is no second factor.
//
// File layout (all binary, big-endian lengths):
//
//	magic      [16]byte  // "tvault-encrypted"
//	version    uint8     // = 1
//	reserved   [3]byte   // = 0
//	salt       [16]byte  // random per file
//	nonce      [12]byte  // random per file
//	ciphertext [...]byte // AES-GCM(salt-derived-key, nonce, dotenv)
//
// The salt is mixed with the vault KEK to derive a file-specific key
// via HKDF-SHA256. This means a single KEK can decrypt many files
// without the files sharing a key, and rotating the KEK invalidates
// every previously encrypted .env file (matches the
// RotatePassphrase semantics).
package encryptedenv

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

const (
	magicLen   = 16
	magicValue = "tvault-encrypted"
	version    = uint8(1)
	headerLen  = magicLen + 1 + 3 + crypto.SaltSize + crypto.NonceSize
)

// ErrInvalidMagic is returned when a file's magic header does not match.
var ErrInvalidMagic = errors.New("not a tvault-encrypted file (magic mismatch)")

// ErrUnsupportedVersion is returned when a file's version byte is not 1.
var ErrUnsupportedVersion = errors.New("unsupported encrypted-env version")

// Encrypt reads plaintext (a .env body) and returns the encrypted file
// bytes. kek is the vault's in-memory KEK.
func Encrypt(kek, plaintext []byte) ([]byte, error) {
	if len(kek) != crypto.KeySize {
		return nil, crypto.ErrInvalidKeySize
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, err
	}

	fileKey, err := deriveFileKey(kek, salt)
	if err != nil {
		return nil, err
	}

	ct, err := crypto.Encrypt(fileKey, plaintext)
	if err != nil {
		return nil, err
	}

	// crypto.Encrypt returns nonce || ciphertext, where nonce is
	// already prepended. Our file format needs salt and nonce in a
	// fixed header, so we strip the auto-prepended nonce and write
	// both nonce and ciphertext into the header explicitly.
	nonce := ct[:crypto.NonceSize]
	body := ct[crypto.NonceSize:]

	buf := make([]byte, 0, headerLen+len(body))
	buf = append(buf, []byte(magicValue)...)
	buf = append(buf, version, 0, 0, 0)
	buf = append(buf, salt...)
	buf = append(buf, nonce...)
	buf = append(buf, body...)
	return buf, nil
}

// Decrypt is the inverse of Encrypt.
func Decrypt(kek, file []byte) ([]byte, error) {
	if len(kek) != crypto.KeySize {
		return nil, crypto.ErrInvalidKeySize
	}
	if len(file) < headerLen {
		return nil, ErrInvalidMagic
	}
	if string(file[:magicLen]) != magicValue {
		return nil, ErrInvalidMagic
	}
	if file[magicLen] != version {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, file[magicLen], version)
	}
	salt := file[magicLen+4 : magicLen+4+crypto.SaltSize]
	nonce := file[magicLen+4+crypto.SaltSize : headerLen]
	body := file[headerLen:]

	fileKey, err := deriveFileKey(kek, salt)
	if err != nil {
		return nil, err
	}

	// Re-prepend the nonce so crypto.Decrypt's layout matches.
	combined := make([]byte, 0, len(nonce)+len(body))
	combined = append(combined, nonce...)
	combined = append(combined, body...)
	return crypto.Decrypt(fileKey, combined)
}

// EncryptReader is a streaming variant for large files. It produces a
// reader whose first bytes are the header followed by the ciphertext.
// We do not chunk; this is mostly here to give callers an io.Reader
// API they can pipe to os.Stdout.
func EncryptReader(kek, plaintext io.Reader) (io.Reader, error) {
	kekBytes, err := io.ReadAll(kek)
	if err != nil {
		return nil, err
	}
	ptBytes, err := io.ReadAll(plaintext)
	if err != nil {
		return nil, err
	}
	out, err := Encrypt(kekBytes, ptBytes)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(out), nil
}

// deriveFileKey derives a per-file key from the vault KEK and a per-file
// salt via HKDF-SHA256. The info string binds the key to this file
// format so a key derived for encrypted-env can never be confused with
// a key derived for another use.
func deriveFileKey(kek, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, kek, salt, []byte("tvault-encrypted-env-v1"))
	out := make([]byte, crypto.KeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}
