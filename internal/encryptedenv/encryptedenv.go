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
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

const (
	magicLen    = 16
	magicValue  = "tvault-encrypted"
	version     = uint8(1) // KEK-tied (passphrase) format
	version2    = uint8(2) // recipient-based, commit-safe, KEK-independent
	headerLen   = magicLen + 1 + 3 + crypto.SaltSize + crypto.NonceSize
	v2PrefixLen = magicLen + 1 + 3 // magic + version + reserved, before the recipient block
)

// ErrInvalidMagic is returned when a file's magic header does not match.
var ErrInvalidMagic = errors.New("not a tvault-encrypted file (magic mismatch)")

// ErrUnsupportedVersion is returned when a file's version byte is not recognized.
var ErrUnsupportedVersion = errors.New("unsupported encrypted-env version")

// ErrMalformed is returned when a v2 file's recipient block is truncated.
var ErrMalformed = errors.New("malformed encrypted-env file")

// FileVersion reads the format version byte from an encrypted-env file so
// callers can dispatch v1 (passphrase) vs v2 (identity) decryption.
func FileVersion(file []byte) (uint8, error) {
	if len(file) < magicLen+1 || string(file[:magicLen]) != magicValue {
		return 0, ErrInvalidMagic
	}
	return file[magicLen], nil
}

// EncryptV2 encrypts plaintext to one or more X25519 recipients, producing a
// commit-safe file that does NOT depend on the vault KEK: any holder of a
// matching private identity can decrypt it (e.g. a teammate, CI, or an
// agent), and rotating the vault passphrase does not invalidate it. A random
// per-file key encrypts the body and is wrapped to each recipient.
//
// v2 layout: magic(16) || version(1)=2 || reserved(3) || count(uint16) ||
//
//	[ stanzaLen(uint16) || stanza ]... || body( crypto.Encrypt(fileKey) )
func EncryptV2(recipients [][]byte, plaintext []byte) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients")
	}
	fileKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(fileKey)

	stanzas, err := crypto.WrapDEK(fileKey, recipients)
	if err != nil {
		return nil, err
	}
	body, err := crypto.Encrypt(fileKey, plaintext) // self-contained nonce||ct
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, v2PrefixLen+2+len(body))
	buf = append(buf, []byte(magicValue)...)
	buf = append(buf, version2, 0, 0, 0)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(stanzas)))
	for _, st := range stanzas {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(st)))
		buf = append(buf, st...)
	}
	buf = append(buf, body...)
	return buf, nil
}

// DecryptV2 decrypts a v2 file using an X25519 identity. Returns
// crypto.ErrNoMatchingRecipient if the identity is not a recipient.
func DecryptV2(id *crypto.Identity, file []byte) ([]byte, error) {
	v, err := FileVersion(file)
	if err != nil {
		return nil, err
	}
	if v != version2 {
		return nil, fmt.Errorf("%w: got %d, want %d (v2)", ErrUnsupportedVersion, v, version2)
	}
	off := v2PrefixLen
	if len(file) < off+2 {
		return nil, ErrMalformed
	}
	count := int(binary.BigEndian.Uint16(file[off:]))
	off += 2
	stanzas := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		if len(file) < off+2 {
			return nil, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(file[off:]))
		off += 2
		if n == 0 || len(file) < off+n {
			return nil, ErrMalformed
		}
		stanzas = append(stanzas, file[off:off+n])
		off += n
	}
	fileKey, err := crypto.UnwrapDEK(id, stanzas)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(fileKey)
	return crypto.Decrypt(fileKey, file[off:])
}

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
