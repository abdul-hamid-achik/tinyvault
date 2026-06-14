package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newQueryTestStore(t *testing.T) *BoltStore {
	t.Helper()
	s, err := NewBoltStore(filepath.Join(t.TempDir(), "query-test.db"))
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func makeProject(t *testing.T, s *BoltStore, name string) *Project {
	t.Helper()
	p := &Project{
		ID:           uuid.New(),
		Name:         name,
		Description:  "test project " + name,
		EncryptedDEK: []byte("dek"),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := s.CreateProject(p); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	return p
}

func makeSecret(t *testing.T, s *BoltStore, projectID uuid.UUID, key string) {
	t.Helper()
	e := &SecretEntry{
		EncryptedValue: []byte("ct-" + key),
		Version:        1,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := s.SetSecret(projectID, key, e); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
}

func TestListSecretKeysFilteredPrefix(t *testing.T) {
	s := newQueryTestStore(t)
	p := makeProject(t, s, "default")
	makeSecret(t, s, p.ID, "STRIPE_KEY")
	makeSecret(t, s, p.ID, "STRIPE_WEBHOOK")
	makeSecret(t, s, p.ID, "DATABASE_URL")
	makeSecret(t, s, p.ID, "API_KEY")

	keys, err := s.ListSecretKeysFiltered(p.ID, SecretFilter{Prefix: "STRIPE"})
	if err != nil {
		t.Fatalf("ListSecretKeysFiltered: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 STRIPE keys, got %d: %v", len(keys), keys)
	}
}

func TestListSecretKeysFilteredNameLike(t *testing.T) {
	s := newQueryTestStore(t)
	p := makeProject(t, s, "default")
	makeSecret(t, s, p.ID, "STRIPE_KEY")
	makeSecret(t, s, p.ID, "STRIPE_WEBHOOK")
	makeSecret(t, s, p.ID, "DATABASE_URL")
	makeSecret(t, s, p.ID, "API_KEY")

	tests := []struct {
		pattern string
		want    int
	}{
		{"STRIPE_*", 2}, // STRIPE_KEY, STRIPE_WEBHOOK
		{"*_KEY", 2},    // STRIPE_KEY, API_KEY
		{"*KEY*", 2},    // STRIPE_KEY, API_KEY (STRIPE_WEBHOOK does not contain "KEY")
		{"*KEY", 2},     // STRIPE_KEY, API_KEY
		{"*HOOK", 1},    // STRIPE_WEBHOOK only
		{"NOTHING*", 0},
	}
	for _, tt := range tests {
		keys, err := s.ListSecretKeysFiltered(p.ID, SecretFilter{NameLike: tt.pattern})
		if err != nil {
			t.Errorf("pattern %q: %v", tt.pattern, err)
			continue
		}
		if len(keys) != tt.want {
			t.Errorf("pattern %q: got %d (%v), want %d", tt.pattern, len(keys), keys, tt.want)
		}
	}
}

func TestListSecretKeysFilteredTimeRange(t *testing.T) {
	s := newQueryTestStore(t)
	p := makeProject(t, s, "default")

	// Insert a secret with a backdated UpdatedAt so the time-range
	// filter has something to bite on.
	old := &SecretEntry{
		EncryptedValue: []byte("ct"),
		Version:        1,
		CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
		UpdatedAt:      time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := s.SetSecret(p.ID, "OLD", old); err != nil {
		t.Fatal(err)
	}
	// And a fresh one.
	makeSecret(t, s, p.ID, "NEW")

	now := time.Now().UTC()
	keys, err := s.ListSecretKeysFiltered(p.ID, SecretFilter{UpdatedAfter: now.Add(-1 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "NEW" {
		t.Errorf("expected [NEW], got %v", keys)
	}

	keys, err = s.ListSecretKeysFiltered(p.ID, SecretFilter{UpdatedBefore: now.Add(-1 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "OLD" {
		t.Errorf("expected [OLD] before -1h, got %v", keys)
	}
}

func TestListSecretKeysFilteredVersion(t *testing.T) {
	s := newQueryTestStore(t)
	p := makeProject(t, s, "default")
	makeSecret(t, s, p.ID, "A")
	makeSecret(t, s, p.ID, "B")
	// Bump A's version by overwriting.
	makeSecret(t, s, p.ID, "A")

	keys, err := s.ListSecretKeysFiltered(p.ID, SecretFilter{VersionAtLeast: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "A" {
		t.Errorf("expected [A], got %v", keys)
	}
}

func TestListSecretsByProject(t *testing.T) {
	s := newQueryTestStore(t)
	p1 := makeProject(t, s, "dev")
	p2 := makeProject(t, s, "prod")
	makeSecret(t, s, p1.ID, "A")
	makeSecret(t, s, p1.ID, "B")
	makeSecret(t, s, p2.ID, "A")

	locs, err := s.ListSecretsByProject(SecretFilter{Prefix: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 2 {
		t.Errorf("expected 2 A keys across projects, got %d", len(locs))
	}

	got := map[string]bool{}
	for _, l := range locs {
		got[l.ProjectName+"/"+l.Key] = true
	}
	if !got["dev/A"] || !got["prod/A"] {
		t.Errorf("missing cross-project results: %v", got)
	}
}

func TestCountSecrets(t *testing.T) {
	s := newQueryTestStore(t)
	p := makeProject(t, s, "default")
	makeSecret(t, s, p.ID, "A")
	makeSecret(t, s, p.ID, "B")
	makeSecret(t, s, p.ID, "C")

	n, err := s.CountSecrets(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("expected 3, got %d", n)
	}
}

func TestListProjectsFiltered(t *testing.T) {
	s := newQueryTestStore(t)
	makeProject(t, s, "production")
	makeProject(t, s, "staging")
	makeProject(t, s, "dev-1")
	makeProject(t, s, "dev-2")

	// NameLike with a '*' wildcard.
	all, err := s.ListProjectsFiltered(ProjectFilter{NameLike: "*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Errorf("expected 4 with '*', got %d", len(all))
	}

	devs, err := s.ListProjectsFiltered(ProjectFilter{NameLike: "dev-*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 {
		t.Errorf("expected 2 dev-*, got %d: %v", len(devs), devs)
	}

	// Limit + offset.
	limited, err := s.ListProjectsFiltered(ProjectFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 2 {
		t.Errorf("expected limit=2 to return 2, got %d", len(limited))
	}
	offset, err := s.ListProjectsFiltered(ProjectFilter{Offset: 1, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(offset) != 2 {
		t.Errorf("expected offset=1 limit=2 to return 2, got %d", len(offset))
	}
}

func TestListProjectsIncludingDeleted(t *testing.T) {
	s := newQueryTestStore(t)
	makeProject(t, s, "alive")
	dead := makeProject(t, s, "doomed")
	if err := s.DeleteProject(dead.ID); err != nil {
		t.Fatal(err)
	}

	visible, err := s.ListProjects()
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 {
		t.Errorf("expected 1 visible, got %d", len(visible))
	}

	all, err := s.ListProjectsIncludingDeleted()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 (incl deleted), got %d", len(all))
	}
}

func TestDeleteConfig(t *testing.T) {
	s := newQueryTestStore(t)
	if err := s.SetConfig("k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.GetConfig("k"); err != nil || v != "v" {
		t.Fatalf("get after set: v=%q err=%v", v, err)
	}
	if err := s.DeleteConfig("k"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetConfig("k"); err == nil {
		t.Error("expected error after delete")
	}
}

func TestListAuditFiltered(t *testing.T) {
	s := newQueryTestStore(t)

	now := time.Now().UTC()
	mustAppend := func(action, resourceType string, ts time.Time) {
		if err := s.AppendAudit(&AuditEntry{
			Action:       action,
			ResourceType: resourceType,
			Timestamp:    ts,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mustAppend("secret.read", "secret", now.Add(-2*time.Hour))
	mustAppend("secret.read", "secret", now.Add(-1*time.Hour))
	mustAppend("secret.write", "secret", now.Add(-30*time.Minute))
	mustAppend("project.create", "project", now.Add(-5*time.Minute))

	// Action filter.
	r, err := s.ListAuditFiltered(AuditFilter{Action: "secret.read"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 2 {
		t.Errorf("expected 2 secret.read entries, got %d", len(r))
	}

	// Time range.
	r, err = s.ListAuditFiltered(AuditFilter{Since: now.Add(-45 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 2 {
		t.Errorf("expected 2 entries in last 45m, got %d", len(r))
	}

	// Resource type.
	r, err = s.ListAuditFiltered(AuditFilter{ResourceType: "project"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 1 {
		t.Errorf("expected 1 project entry, got %d", len(r))
	}

	// Limit.
	r, err = s.ListAuditFiltered(AuditFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 2 {
		t.Errorf("expected limit=2 to return 2, got %d", len(r))
	}
}

func TestCountAudit(t *testing.T) {
	s := newQueryTestStore(t)
	for i := 0; i < 5; i++ {
		if err := s.AppendAudit(&AuditEntry{
			Action: "secret.read", ResourceType: "secret", Timestamp: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.CountAudit()
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("expected 5, got %d", n)
	}
}

func TestMatchLike(t *testing.T) {
	tests := []struct {
		s, pattern string
		want       bool
	}{
		{"STRIPE_KEY", "STRIPE_KEY", true},
		{"STRIPE_KEY", "STRIPE_*", true},
		{"STRIPE_KEY", "*_KEY", true},
		{"STRIPE_KEY", "*KEY*", true},
		{"STRIPE_KEY", "*DB*", false},
		{"STRIPE_KEY", "STRIPE_*_KEY", true},
		{"STRIPE_KEY", "ST*_*KEY", true},
		{"", "", true},
		{"", "*", true},
		{"", "x", false},
	}
	for _, tt := range tests {
		if got := matchLike(tt.s, tt.pattern); got != tt.want {
			t.Errorf("matchLike(%q, %q) = %v, want %v", tt.s, tt.pattern, got, tt.want)
		}
	}
}
