package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Asymmetric recipient layer (Spine A).
//
// This wraps a symmetric key (a project DEK) so it can be opened by any
// holder of a matching X25519 private key — the foundation for sharing and
// committing secrets without distributing the master passphrase. The scheme
// is the standard ECIES / age sealed-box construction:
//
//	ephemeral X25519 keypair → ECDH(eph_priv, recipient_pub) = shared
//	wrap_key = HKDF-SHA256(shared, salt = eph_pub||recipient_pub, info)
//	stanza   = version || eph_pub || nonce || ChaCha20-Poly1305(wrap_key, DEK)
//
// One stanza is produced per recipient; the same DEK is wrapped to each, so
// any recipient (or the local KEK path, kept separately) can unwrap it.
//
// crypto/ecdh (stdlib) is used for X25519: it handles scalar clamping and
// rejects low-order / invalid points at ECDH time (NewPublicKey accepts any
// 32 bytes, so DecodeRecipient probes the key with a throwaway ECDH to catch
// bad keys at import rather than confusingly later). Only chacha20poly1305
// and hkdf come from x/crypto, both already vendored — no new dependency.

const (
	// X25519KeySize is the size of an X25519 public or private key.
	X25519KeySize = 32

	// recipientStanzaV1 is the version byte for the v1 stanza format
	// (X25519 + HKDF-SHA256 + ChaCha20-Poly1305). Versioned for agility.
	recipientStanzaV1 byte = 0x01

	// hkdfInfo domain-separates this construction from any other use of the
	// same ECDH output.
	hkdfInfo = "tvault-recipient-v1"

	// recipientHRP / identityHRP prefix the human-shareable encodings.
	recipientHRP = "tvault1"     // public recipient: shareable, commit-safe
	identityHRP  = "tvault-key1" // private identity: secret, 0600 file only
)

// stanza layout: version(1) || eph_pub(32) || nonce(12) || ciphertext(N+16)
const stanzaHeaderLen = 1 + X25519KeySize + chacha20poly1305.NonceSize

var (
	// ErrNoMatchingRecipient is returned by UnwrapDEK when none of the
	// stanzas can be opened with the given identity.
	ErrNoMatchingRecipient = errors.New("no stanza could be opened by this identity")

	// ErrInvalidRecipient is returned when a recipient/identity string or
	// key cannot be parsed.
	ErrInvalidRecipient = errors.New("invalid recipient or identity")

	// ErrInvalidStanza is returned when a stanza is malformed.
	ErrInvalidStanza = errors.New("malformed recipient stanza")
)

// b32 is lowercase, unpadded base32 (RFC 4648, no padding) for compact,
// case-insensitive, copy-paste-safe key strings.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Identity is an X25519 keypair. The private half decrypts stanzas wrapped
// to the corresponding public recipient.
type Identity struct {
	priv *ecdh.PrivateKey
}

// GenerateIdentity creates a new random X25519 identity.
func GenerateIdentity() (*Identity, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 identity: %w", err)
	}
	return &Identity{priv: priv}, nil
}

// Recipient returns the public recipient bytes (32 bytes).
func (id *Identity) Recipient() []byte { return id.priv.PublicKey().Bytes() }

// privBytes returns the raw private scalar (32 bytes). Callers must zero it.
func (id *Identity) privBytes() []byte { return id.priv.Bytes() }

// EncodeRecipient renders a public recipient as a shareable string
// (tvault1…). Safe to publish, commit, and put in a .tvault-recipients file.
func EncodeRecipient(pub []byte) string {
	return recipientHRP + strings.ToLower(b32.EncodeToString(pub))
}

// DecodeRecipient parses a tvault1… recipient string back to public bytes.
func DecodeRecipient(s string) ([]byte, error) {
	body, ok := strings.CutPrefix(strings.TrimSpace(s), recipientHRP)
	if !ok {
		return nil, fmt.Errorf("%w: recipient must start with %q", ErrInvalidRecipient, recipientHRP)
	}
	pub, err := b32.DecodeString(strings.ToUpper(body))
	if err != nil || len(pub) != X25519KeySize {
		return nil, fmt.Errorf("%w: bad recipient encoding", ErrInvalidRecipient)
	}
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRecipient, err.Error())
	}
	// NewPublicKey accepts any 32 bytes; the low-order / identity-point
	// rejection happens at ECDH time. Probe with a throwaway ECDH so a bad
	// recipient is caught here (at import / validation) rather than failing
	// the whole batch later in WrapDEK.
	probe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := probe.ECDH(pk)
	if err != nil {
		return nil, fmt.Errorf("%w: unusable key: %s", ErrInvalidRecipient, err.Error())
	}
	ZeroBytes(shared)
	return pub, nil
}

// EncodeIdentity renders a private identity as a tvault-key1… string for
// storage in a 0600 file. NEVER share or commit this.
func EncodeIdentity(id *Identity) string {
	return identityHRP + strings.ToLower(b32.EncodeToString(id.privBytes()))
}

// DecodeIdentity parses a tvault-key1… identity string back to an Identity.
func DecodeIdentity(s string) (*Identity, error) {
	body, ok := strings.CutPrefix(strings.TrimSpace(s), identityHRP)
	if !ok {
		return nil, fmt.Errorf("%w: identity must start with %q", ErrInvalidRecipient, identityHRP)
	}
	raw, err := b32.DecodeString(strings.ToUpper(body))
	if err != nil || len(raw) != X25519KeySize {
		return nil, fmt.Errorf("%w: bad identity encoding", ErrInvalidRecipient)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	ZeroBytes(raw) // NewPrivateKey copies; clear our transient scalar copy
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRecipient, err.Error())
	}
	return &Identity{priv: priv}, nil
}

// WrapDEK wraps dek to each recipient public key, returning one stanza per
// recipient. Each stanza is independently openable by exactly one identity.
func WrapDEK(dek []byte, recipients [][]byte) ([][]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients")
	}
	curve := ecdh.X25519()
	stanzas := make([][]byte, 0, len(recipients))
	for _, rpub := range recipients {
		recipientKey, err := curve.NewPublicKey(rpub)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidRecipient, err.Error())
		}
		eph, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ephemeral key: %w", err)
		}
		shared, err := eph.ECDH(recipientKey)
		if err != nil {
			return nil, fmt.Errorf("ecdh: %w", err)
		}
		ephPub := eph.PublicKey().Bytes()
		wrapKey, err := deriveWrapKey(shared, ephPub, rpub)
		ZeroBytes(shared)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(wrapKey)
		ZeroBytes(wrapKey)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
		stanza := make([]byte, 0, stanzaHeaderLen+len(dek)+aead.Overhead())
		stanza = append(stanza, recipientStanzaV1)
		stanza = append(stanza, ephPub...)
		stanza = append(stanza, nonce...)
		stanza = aead.Seal(stanza, nonce, dek, ephPub) // AAD = ephPub binds header
		stanzas = append(stanzas, stanza)
	}
	return stanzas, nil
}

// UnwrapDEK tries each stanza with the identity and returns the DEK from the
// first that opens. Returns ErrNoMatchingRecipient if none match.
func UnwrapDEK(id *Identity, stanzas [][]byte) ([]byte, error) {
	mypub := id.Recipient()
	for _, st := range stanzas {
		dek, err := unwrapOne(id, mypub, st)
		if err == nil {
			return dek, nil
		}
	}
	return nil, ErrNoMatchingRecipient
}

func unwrapOne(id *Identity, mypub, st []byte) ([]byte, error) {
	if len(st) < stanzaHeaderLen+chacha20poly1305.Overhead || st[0] != recipientStanzaV1 {
		return nil, ErrInvalidStanza
	}
	ephPub := st[1 : 1+X25519KeySize]
	nonce := st[1+X25519KeySize : stanzaHeaderLen]
	ct := st[stanzaHeaderLen:]

	ephKey, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, err
	}
	shared, err := id.priv.ECDH(ephKey)
	if err != nil {
		return nil, err
	}
	wrapKey, err := deriveWrapKey(shared, ephPub, mypub)
	ZeroBytes(shared)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(wrapKey)
	ZeroBytes(wrapKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, ephPub)
}

// deriveWrapKey derives the per-stanza 32-byte wrapping key from the ECDH
// shared secret, bound to both public keys via the HKDF salt.
func deriveWrapKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(recipientPub))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)
	r := hkdf.New(sha256.New, shared, salt, []byte(hkdfInfo))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}
