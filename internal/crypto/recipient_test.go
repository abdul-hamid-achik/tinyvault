package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func newDEK(t *testing.T) []byte {
	t.Helper()
	dek, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return dek
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	dek := newDEK(t)
	stanzas, err := WrapDEK(dek, [][]byte{id.Recipient()})
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	got, err := UnwrapDEK(id, stanzas)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestMultiRecipient(t *testing.T) {
	ids := make([]*Identity, 3)
	recips := make([][]byte, 3)
	for i := range ids {
		id, _ := GenerateIdentity()
		ids[i] = id
		recips[i] = id.Recipient()
	}
	dek := newDEK(t)
	stanzas, err := WrapDEK(dek, recips)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(stanzas) != 3 {
		t.Fatalf("want 3 stanzas, got %d", len(stanzas))
	}
	// Every recipient can unwrap.
	for i, id := range ids {
		got, err := UnwrapDEK(id, stanzas)
		if err != nil || !bytes.Equal(got, dek) {
			t.Errorf("recipient %d failed to unwrap: %v", i, err)
		}
	}
	// A non-recipient cannot.
	outsider, _ := GenerateIdentity()
	if _, err := UnwrapDEK(outsider, stanzas); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Errorf("outsider should not unwrap, got %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	id, _ := GenerateIdentity()
	dek := newDEK(t)
	stanzas, _ := WrapDEK(dek, [][]byte{id.Recipient()})

	// Flip a ciphertext byte.
	bad := append([]byte(nil), stanzas[0]...)
	bad[len(bad)-1] ^= 0xff
	if _, err := UnwrapDEK(id, [][]byte{bad}); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Error("tampered ciphertext should not open")
	}

	// Flip an ephemeral-pubkey byte (it is also AAD).
	bad2 := append([]byte(nil), stanzas[0]...)
	bad2[2] ^= 0xff
	if _, err := UnwrapDEK(id, [][]byte{bad2}); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Error("tampered header should not open")
	}
}

func TestStanzaUniqueness(t *testing.T) {
	id, _ := GenerateIdentity()
	dek := newDEK(t)
	a, _ := WrapDEK(dek, [][]byte{id.Recipient()})
	b, _ := WrapDEK(dek, [][]byte{id.Recipient()})
	if bytes.Equal(a[0], b[0]) {
		t.Error("wrapping the same DEK twice must yield different stanzas (fresh ephemeral + nonce)")
	}
}

func TestWrapNoRecipients(t *testing.T) {
	if _, err := WrapDEK(newDEK(t), nil); err == nil {
		t.Error("WrapDEK with no recipients should error")
	}
}

func TestUnwrapMalformedStanza(t *testing.T) {
	id, _ := GenerateIdentity()
	for _, st := range [][]byte{nil, {}, {0x01}, {0x02, 1, 2, 3}, make([]byte, 200)} {
		if _, err := UnwrapDEK(id, [][]byte{st}); err == nil {
			t.Errorf("malformed stanza %v should not open", st)
		}
	}
}

func TestRecipientEncodingRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity()
	s := EncodeRecipient(id.Recipient())
	if s[:len(recipientHRP)] != recipientHRP {
		t.Errorf("recipient string missing prefix: %s", s)
	}
	pub, err := DecodeRecipient(s)
	if err != nil || !bytes.Equal(pub, id.Recipient()) {
		t.Errorf("recipient round-trip failed: %v", err)
	}
	// Case-insensitive.
	if _, err := DecodeRecipient(recipientHRP + "ABCDEF"); err == nil {
		t.Error("short recipient body should fail")
	}
}

func TestIdentityEncodingRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity()
	s := EncodeIdentity(id)
	id2, err := DecodeIdentity(s)
	if err != nil {
		t.Fatalf("DecodeIdentity: %v", err)
	}
	if !bytes.Equal(id2.Recipient(), id.Recipient()) {
		t.Error("identity round-trip changed the public key")
	}
	// A decoded identity unwraps what was wrapped to the original recipient.
	dek := newDEK(t)
	stanzas, _ := WrapDEK(dek, [][]byte{id.Recipient()})
	got, err := UnwrapDEK(id2, stanzas)
	if err != nil || !bytes.Equal(got, dek) {
		t.Errorf("decoded identity failed to unwrap: %v", err)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "nope", "tvault1", "tvault1!!!", "age1abcdef", recipientHRP + "00000000"} {
		if _, err := DecodeRecipient(s); err == nil {
			t.Errorf("DecodeRecipient(%q) should fail", s)
		}
	}
	if _, err := DecodeIdentity("nope"); err == nil {
		t.Error("DecodeIdentity should reject a non-identity string")
	}
}

func TestDecodeRecipientRejectsLowOrderPoints(t *testing.T) {
	// Properly base32-encoded but cryptographically unusable points: the
	// all-zero/identity point and u=1. NewPublicKey accepts these, so
	// DecodeRecipient must catch them via its ECDH probe.
	lowOrder := [][]byte{
		make([]byte, X25519KeySize),                         // all zero (identity)
		append([]byte{1}, make([]byte, X25519KeySize-1)...), // u = 1
	}
	for _, pt := range lowOrder {
		s := EncodeRecipient(pt)
		if _, err := DecodeRecipient(s); err == nil {
			t.Errorf("DecodeRecipient must reject low-order point %x", pt)
		}
	}
	// A real recipient still decodes fine.
	id, _ := GenerateIdentity()
	if _, err := DecodeRecipient(EncodeRecipient(id.Recipient())); err != nil {
		t.Errorf("valid recipient rejected: %v", err)
	}
}

func TestRecipientAndIdentityPrefixesDiffer(t *testing.T) {
	// A recipient string must not parse as an identity, or vice versa.
	id, _ := GenerateIdentity()
	if _, err := DecodeIdentity(EncodeRecipient(id.Recipient())); err == nil {
		t.Error("a recipient string must not decode as an identity")
	}
	if _, err := DecodeRecipient(EncodeIdentity(id)); err == nil {
		t.Error("an identity string must not decode as a recipient")
	}
}
