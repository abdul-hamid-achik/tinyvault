package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

func putSecret(t *testing.T, s *BoltStore, proj uuid.UUID, key, ct string) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.SetSecret(proj, key, &SecretEntry{
		EncryptedValue: []byte(ct), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("SetSecret %s: %v", key, err)
	}
}

func TestSetSecretArchivesOldVersion(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	putSecret(t, s, proj, "K", "ct1")
	putSecret(t, s, proj, "K", "ct2")
	putSecret(t, s, proj, "K", "ct3")

	// Current is v3.
	cur, err := s.GetSecret(proj, "K")
	if err != nil || cur.Version != 3 {
		t.Fatalf("current version = %v (err %v), want 3", cur, err)
	}
	// History holds v1 and v2 only.
	hist, err := s.ListSecretVersionEntries(proj)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("archived versions = %d, want 2", len(hist))
	}
	got := map[int]string{}
	for _, h := range hist {
		got[h.Entry.Version] = string(h.Entry.EncryptedValue)
	}
	if got[1] != "ct1" || got[2] != "ct2" {
		t.Errorf("archived ciphertexts wrong: %v", got)
	}
}

func TestSecretVersionKeyPrefixIsolation(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	// "A" and "AB" share a prefix; their version scans must not bleed.
	putSecret(t, s, proj, "A", "a1")
	putSecret(t, s, proj, "A", "a2")
	putSecret(t, s, proj, "AB", "ab1")
	putSecret(t, s, proj, "AB", "ab2")

	va, err := s.ListSecretVersions(proj, "A")
	if err != nil {
		t.Fatal(err)
	}
	if len(va) != 2 {
		t.Fatalf("ListSecretVersions(A) = %d versions, want 2 (no AB bleed)", len(va))
	}
	vab, err := s.ListSecretVersions(proj, "AB")
	if err != nil {
		t.Fatal(err)
	}
	if len(vab) != 2 {
		t.Fatalf("ListSecretVersions(AB) = %d versions, want 2", len(vab))
	}
}

func TestGetSecretVersionCurrentArchivedMissing(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	putSecret(t, s, proj, "K", "ct1")
	putSecret(t, s, proj, "K", "ct2")
	putSecret(t, s, proj, "K", "ct3")

	for v, want := range map[int]string{1: "ct1", 2: "ct2", 3: "ct3"} {
		e, err := s.GetSecretVersion(proj, "K", v)
		if err != nil {
			t.Fatalf("GetSecretVersion(%d): %v", v, err)
		}
		if string(e.EncryptedValue) != want {
			t.Errorf("v%d = %q, want %q", v, e.EncryptedValue, want)
		}
	}
	if _, err := s.GetSecretVersion(proj, "K", 99); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("missing version should be ErrSecretNotFound, got %v", err)
	}
	if _, err := s.GetSecretVersion(proj, "NOPE", 1); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("missing key should be ErrSecretNotFound, got %v", err)
	}
}

func TestListSecretVersionsAscendingWithCurrent(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	putSecret(t, s, proj, "K", "ct1")
	putSecret(t, s, proj, "K", "ct2")
	putSecret(t, s, proj, "K", "ct3")

	vs, err := s.ListSecretVersions(proj, "K")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 3 {
		t.Fatalf("want 3 versions, got %d", len(vs))
	}
	for i, v := range vs {
		if v.Version != i+1 {
			t.Errorf("position %d has version %d, want %d (ascending)", i, v.Version, i+1)
		}
	}
	if _, err := s.ListSecretVersions(proj, "NEVER"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("unknown key should be ErrSecretNotFound, got %v", err)
	}
}

func TestGetSecretVersionCorrupt(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	putSecret(t, s, proj, "K", "ct1")
	putSecret(t, s, proj, "K", "ct2") // archives v1

	// Corrupt the archived v1 entry directly.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecretVersions).Put(secretVersionKey(proj, "K", 1), []byte("{not json"))
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetSecretVersion(proj, "K", 1)
	if err == nil || errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("corrupt version should surface a wrapped error, got %v", err)
	}
}

func TestDeleteSecretPurgesHistory(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	putSecret(t, s, proj, "K", "ct1")
	putSecret(t, s, proj, "K", "ct2")
	putSecret(t, s, proj, "K", "ct3")

	if err := s.DeleteSecret(proj, "K"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := s.GetSecret(proj, "K"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("current should be gone, got %v", err)
	}
	hist, err := s.ListSecretVersionEntries(proj)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 0 {
		t.Errorf("history should be purged, got %d entries", len(hist))
	}
	if err := s.DeleteSecret(proj, "K"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("deleting a gone secret should be ErrSecretNotFound, got %v", err)
	}
}

func TestSetSecretNewKeyVersionIsOne(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	// Caller lies about the version; the store must floor a new key to v1.
	if err := s.SetSecret(proj, "K", &SecretEntry{EncryptedValue: []byte("x"), Version: 99}); err != nil {
		t.Fatal(err)
	}
	cur, err := s.GetSecret(proj, "K")
	if err != nil {
		t.Fatal(err)
	}
	if cur.Version != 1 {
		t.Errorf("new key version = %d, want 1", cur.Version)
	}
}

func TestRekeyProjectWritesHistory(t *testing.T) {
	s := newTestStore(t)
	proj := &Project{ID: uuid.New(), Name: "p", EncryptedDEK: []byte("dek"), CreatedAt: time.Now().UTC()}
	if err := s.CreateProject(proj); err != nil {
		t.Fatal(err)
	}
	secrets := map[string]*SecretEntry{
		"K": {EncryptedValue: []byte("new-current"), Version: 3},
	}
	history := []VersionedSecret{
		{Key: "K", Entry: &SecretEntry{EncryptedValue: []byte("new-v1"), Version: 1}},
		{Key: "K", Entry: &SecretEntry{EncryptedValue: []byte("new-v2"), Version: 2}},
	}
	if err := s.RekeyProject(proj, secrets, history); err != nil {
		t.Fatalf("RekeyProject: %v", err)
	}
	for v, want := range map[int]string{1: "new-v1", 2: "new-v2", 3: "new-current"} {
		e, err := s.GetSecretVersion(proj.ID, "K", v)
		if err != nil {
			t.Fatalf("GetSecretVersion(%d): %v", v, err)
		}
		if string(e.EncryptedValue) != want {
			t.Errorf("v%d = %q, want %q", v, e.EncryptedValue, want)
		}
	}
}

func TestOldVaultUpgradeCreatesVersionBucket(t *testing.T) {
	path := t.TempDir() + "/old.db"
	s := newStoreAt(t, path)
	proj := uuid.New()
	putSecret(t, s, proj, "K", "ct1")

	// Simulate a pre-feature vault: drop the versions bucket, then reopen.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket(bucketSecretVersions)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := newStoreAt(t, path)
	// Bucket recreated; an existing secret shows a single (current) version.
	vs, err := s2.ListSecretVersions(proj, "K")
	if err != nil {
		t.Fatalf("ListSecretVersions after upgrade: %v", err)
	}
	if len(vs) != 1 || vs[0].Version != 1 {
		t.Errorf("upgraded vault should show 1 current version, got %v", vs)
	}
	// The original current ciphertext must survive the bucket recreation.
	cur, err := s2.GetSecret(proj, "K")
	if err != nil {
		t.Fatalf("GetSecret after upgrade: %v", err)
	}
	if string(cur.EncryptedValue) != "ct1" {
		t.Errorf("current ciphertext changed by upgrade: %q", cur.EncryptedValue)
	}
}

func TestDeleteThenRecreateStartsAtV1(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	putSecret(t, s, proj, "K", "a")
	putSecret(t, s, proj, "K", "b") // archives v1, current v2
	if err := s.DeleteSecret(proj, "K"); err != nil {
		t.Fatal(err)
	}
	// Recreating a purged key must restart at v1 with no stale history.
	putSecret(t, s, proj, "K", "fresh")
	vs, err := s.ListSecretVersions(proj, "K")
	if err != nil {
		t.Fatalf("ListSecretVersions after recreate: %v", err)
	}
	if len(vs) != 1 || vs[0].Version != 1 {
		t.Errorf("recreated key should be a single v1, got %v", vs)
	}
}

func TestRekeyProjectMultipleKeysWithHistory(t *testing.T) {
	s := newTestStore(t)
	proj := &Project{ID: uuid.New(), Name: "p", EncryptedDEK: []byte("dek"), CreatedAt: time.Now().UTC()}
	if err := s.CreateProject(proj); err != nil {
		t.Fatal(err)
	}
	// Three distinct keys, each with two archived versions — exercises the
	// LastIndex("/") key-name recovery in ListSecretVersionEntries.
	secrets := map[string]*SecretEntry{}
	history := make([]VersionedSecret, 0, 6)
	for _, k := range []string{"ALPHA", "BETA", "GAMMA"} {
		secrets[k] = &SecretEntry{EncryptedValue: []byte("cur-" + k), Version: 3}
		history = append(history,
			VersionedSecret{Key: k, Entry: &SecretEntry{EncryptedValue: []byte("v1-" + k), Version: 1}},
			VersionedSecret{Key: k, Entry: &SecretEntry{EncryptedValue: []byte("v2-" + k), Version: 2}},
		)
	}
	if err := s.RekeyProject(proj, secrets, history); err != nil {
		t.Fatalf("RekeyProject: %v", err)
	}
	for _, k := range []string{"ALPHA", "BETA", "GAMMA"} {
		for v, want := range map[int]string{1: "v1-" + k, 2: "v2-" + k, 3: "cur-" + k} {
			e, err := s.GetSecretVersion(proj.ID, k, v)
			if err != nil {
				t.Fatalf("GetSecretVersion(%s,%d): %v", k, v, err)
			}
			if string(e.EncryptedValue) != want {
				t.Errorf("%s v%d = %q, want %q", k, v, e.EncryptedValue, want)
			}
		}
	}
}

func TestListSecretVersionsErrorsOnCorrupt(t *testing.T) {
	s := newTestStore(t)
	proj := uuid.New()
	putSecret(t, s, proj, "K", "a")
	putSecret(t, s, proj, "K", "b") // archives v1
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecretVersions).Put(secretVersionKey(proj, "K", 1), []byte("{bad"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListSecretVersions(proj, "K"); err == nil {
		t.Error("ListSecretVersions should surface a corrupt archived entry")
	}
	if _, err := s.ListSecretVersionEntries(proj); err == nil {
		t.Error("ListSecretVersionEntries should surface a corrupt archived entry")
	}
}

func newStoreAt(t *testing.T, path string) *BoltStore {
	t.Helper()
	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
