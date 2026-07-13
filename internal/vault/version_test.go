package vault

import (
	"errors"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

func TestRollbackCreatesNewVersion(t *testing.T) {
	v := createTestVault(t)
	for _, val := range []string{"a", "b", "c"} {
		if err := v.SetSecret("default", "K", val); err != nil {
			t.Fatal(err)
		}
	}
	newVer, err := v.RollbackSecret("default", "K", 1)
	if err != nil {
		t.Fatalf("RollbackSecret: %v", err)
	}
	if newVer != 4 {
		t.Errorf("new version = %d, want 4", newVer)
	}
	got, err := v.GetSecret("default", "K")
	if err != nil || got != "a" {
		t.Errorf("after rollback current = %q (err %v), want \"a\"", got, err)
	}
	vs, err := v.ListSecretVersions("default", "K")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 4 {
		t.Errorf("want 4 versions after rollback, got %d", len(vs))
	}
}

func TestRollbackToNonexistentVersion(t *testing.T) {
	v := createTestVault(t)
	if err := v.SetSecret("default", "K", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.RollbackSecret("default", "K", 99); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("rollback to missing version should be ErrSecretNotFound, got %v", err)
	}
}

func TestRollbackMonotonic(t *testing.T) {
	v := createTestVault(t)
	for _, val := range []string{"a", "b"} {
		if err := v.SetSecret("default", "K", val); err != nil {
			t.Fatal(err)
		}
	}
	n1, err := v.RollbackSecret("default", "K", 1) // -> v3 (= "a")
	if err != nil {
		t.Fatal(err)
	}
	n2, err := v.RollbackSecret("default", "K", 1) // -> v4 (= "a")
	if err != nil {
		t.Fatal(err)
	}
	if n1 != 3 || n2 != 4 {
		t.Errorf("versions must increase monotonically, got %d then %d", n1, n2)
	}
}

func TestRollbackSequenceDifferentVersions(t *testing.T) {
	v := createTestVault(t)
	for _, val := range []string{"a", "b", "c"} {
		if err := v.SetSecret("default", "K", val); err != nil {
			t.Fatal(err)
		}
	}
	// Roll back to v1 (-> v4="a"), then to v2 (-> v5="b"). The version made by
	// the first rollback must itself be archived and recoverable.
	if n, err := v.RollbackSecret("default", "K", 1); err != nil || n != 4 {
		t.Fatalf("first rollback: n=%d err=%v", n, err)
	}
	if got, _ := v.GetSecret("default", "K"); got != "a" {
		t.Errorf("after rollback to v1, current = %q, want a", got)
	}
	if n, err := v.RollbackSecret("default", "K", 2); err != nil || n != 5 {
		t.Fatalf("second rollback: n=%d err=%v", n, err)
	}
	if got, _ := v.GetSecret("default", "K"); got != "b" {
		t.Errorf("after rollback to v2, current = %q, want b", got)
	}
	// v4 (the first rollback's result, = "a") is archived and recoverable.
	if got, err := v.GetSecretVersionValue("default", "K", 4); err != nil || got != "a" {
		t.Errorf("archived v4 = %q (err %v), want a", got, err)
	}
	vs, err := v.ListSecretVersions("default", "K")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 5 {
		t.Errorf("want 5 versions after two rollbacks, got %d", len(vs))
	}
}

func TestGetSecretVersionValue(t *testing.T) {
	v := createTestVault(t)
	for _, val := range []string{"a", "b", "c"} {
		if err := v.SetSecret("default", "K", val); err != nil {
			t.Fatal(err)
		}
	}
	for ver, want := range map[int]string{1: "a", 2: "b", 3: "c"} {
		got, err := v.GetSecretVersionValue("default", "K", ver)
		if err != nil {
			t.Fatalf("GetSecretVersionValue(%d): %v", ver, err)
		}
		if got != want {
			t.Errorf("v%d = %q, want %q", ver, got, want)
		}
	}
}

func TestGetSecretVersionValueLockedFails(t *testing.T) {
	v := createTestVault(t)
	if err := v.SetSecret("default", "K", "a"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if _, err := v.GetSecretVersionValue("default", "K", 1); !errors.Is(err, ErrLocked) {
		t.Errorf("version read on a locked vault should return ErrLocked, got %v", err)
	}
}

func TestListSecretVersionsNoUnlockNeeded(t *testing.T) {
	v := createTestVault(t)
	if err := v.SetSecret("default", "K", "a"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "K", "b"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	vs, err := v.ListSecretVersions("default", "K")
	if err != nil {
		t.Fatalf("ListSecretVersions on a locked vault: %v", err)
	}
	if len(vs) != 2 {
		t.Errorf("want 2 versions, got %d", len(vs))
	}
}

// TestUnshareReEncryptsHistory is the regression guard for the top design
// risk: removing a recipient rotates the live vault's DEK, and history must be
// re-encrypted under the new DEK or rollback to a pre-removal version would
// break. Pre-removal snapshots remain readable under the old DEK.
func TestUnshareReEncryptsHistory(t *testing.T) {
	v := createTestVault(t)
	for _, val := range []string{"db-v1", "db-v2", "db-v3"} {
		if err := v.SetSecret("default", "DB", val); err != nil {
			t.Fatal(err)
		}
	}
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	if err := v.ShareProject("default", alice.Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := v.ShareProject("default", bob.Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := v.UnshareProject("default", bob.Recipient()); err != nil {
		t.Fatalf("UnshareProject: %v", err)
	}

	// History (encrypted under the OLD DEK) must still decrypt under the NEW one.
	for ver, want := range map[int]string{1: "db-v1", 2: "db-v2", 3: "db-v3"} {
		got, err := v.GetSecretVersionValue("default", "DB", ver)
		if err != nil {
			t.Fatalf("post-rotation GetSecretVersionValue(%d): %v", ver, err)
		}
		if got != want {
			t.Errorf("post-rotation v%d = %q, want %q", ver, got, want)
		}
	}
	// And rollback to a pre-rotation version works end to end.
	if _, err := v.RollbackSecret("default", "DB", 1); err != nil {
		t.Fatalf("post-rotation rollback: %v", err)
	}
	if got, _ := v.GetSecret("default", "DB"); got != "db-v1" {
		t.Errorf("rolled-back value = %q, want db-v1", got)
	}
}

func TestRotatePassphraseSurvivesHistory(t *testing.T) {
	v := createTestVault(t)
	if err := v.SetSecret("default", "K", "a"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "K", "b"); err != nil {
		t.Fatal(err)
	}
	before, err := v.ListSecretVersions("default", "K")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RotatePassphrase(testPassphrase, "new-passphrase-123"); err != nil {
		t.Fatalf("RotatePassphrase: %v", err)
	}
	// KEK rotation does not touch values; history still decrypts.
	got, err := v.GetSecretVersionValue("default", "K", 1)
	if err != nil || got != "a" {
		t.Errorf("post-KEK-rotation v1 = %q (err %v), want \"a\"", got, err)
	}
	// Timestamps are unchanged (values were never re-written).
	after, err := v.ListSecretVersions("default", "K")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || !after[0].CreatedAt.Equal(before[0].CreatedAt) {
		t.Errorf("history timestamps changed by KEK rotation: before=%v after=%v", before, after)
	}
	// And rollback still works after a passphrase rotation.
	if _, err := v.RollbackSecret("default", "K", 1); err != nil {
		t.Errorf("rollback after KEK rotation failed: %v", err)
	}
	if cur, _ := v.GetSecret("default", "K"); cur != "a" {
		t.Errorf("rolled-back value after rotation = %q, want a", cur)
	}
}
