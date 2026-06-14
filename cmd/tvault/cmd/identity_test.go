package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

func TestIdentityNewListRoundTrip(t *testing.T) {
	dir := t.TempDir()
	oldVaultDir, oldJSON := vaultDir, jsonOutput
	t.Cleanup(func() { vaultDir, jsonOutput = oldVaultDir, oldJSON })
	vaultDir, jsonOutput = dir, false

	if err := runIdentityNew(nil, []string{"ci"}); err != nil {
		t.Fatalf("identity new: %v", err)
	}
	// Duplicate must not overwrite.
	if err := runIdentityNew(nil, []string{"ci"}); err == nil {
		t.Error("creating a duplicate identity should fail")
	}
	// Invalid / path-traversal names rejected.
	for _, bad := range []string{"../evil", "a/b", "has space", ""} {
		if err := runIdentityNew(nil, []string{bad}); err == nil {
			t.Errorf("invalid identity name %q should be rejected", bad)
		}
	}

	// Key file is 0600 and loadable.
	path := filepath.Join(identitiesDir(), "ci.key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file perms = %#o, want 0600", perm)
	}
	id, err := loadIdentity(path)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}

	// End-to-end: a DEK wrapped to this identity's recipient round-trips
	// through the on-disk identity.
	dek, _ := crypto.GenerateKey()
	stanzas, err := crypto.WrapDEK(dek, [][]byte{id.Recipient()})
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	got, err := crypto.UnwrapDEK(id, stanzas)
	if err != nil || !bytes.Equal(got, dek) {
		t.Errorf("on-disk identity failed to unwrap: %v", err)
	}

	if err := runIdentityList(nil, nil); err != nil {
		t.Errorf("identity list: %v", err)
	}
}

func TestLoadIdentitySkipsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.key")
	id, _ := crypto.GenerateIdentity()
	content := "# comment\n\n# recipient: " + crypto.EncodeRecipient(id.Recipient()) + "\n" + crypto.EncodeIdentity(id) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadIdentity(path)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if !bytes.Equal(got.Recipient(), id.Recipient()) {
		t.Error("loaded identity does not match")
	}
}
