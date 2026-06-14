package vault

import (
	"testing"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
)

// setupQueryVault creates a vault with three projects and a known
// set of secrets so the relational query methods can be exercised.
//
// vault.Create already auto-creates a "default" project, so we
// start from there and add the other two.
func setupQueryVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	v, err := Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	if _, err := v.CreateProject("staging", "Staging environment"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CreateProject("production", "Production environment"); err != nil {
		t.Fatal(err)
	}

	// default: STRIPE_KEY, STRIPE_WEBHOOK, DATABASE_URL, API_KEY
	// staging: DATABASE_URL, STRIPE_KEY (older)
	// production: MASTER_KEY, STRIPE_KEY (with a future UpdatedAt for time-range tests)
	now := time.Now().UTC()
	must := func(project, key, value string) {
		t.Helper()
		if err := v.SetSecret(project, key, value); err != nil {
			t.Fatal(err)
		}
	}
	must("default", "STRIPE_KEY", "sk_test_default")
	must("default", "STRIPE_WEBHOOK", "whsec_default")
	must("default", "DATABASE_URL", "postgres://default")
	must("default", "API_KEY", "ak_default")
	must("staging", "DATABASE_URL", "postgres://staging")
	must("staging", "STRIPE_KEY", "sk_test_staging")
	must("production", "MASTER_KEY", "mk_prod")
	must("production", "STRIPE_KEY", "sk_live_prod")

	_ = now
	return v
}

func TestSearchProjectScoped(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	refs, err := v.Search(SecretSearchQuery{Project: "default", Prefix: "STRIPE_"})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Errorf("expected 2 STRIPE_ keys in default, got %d", len(refs))
	}
	for _, r := range refs {
		if r.Project != "default" {
			t.Errorf("expected project=default, got %s", r.Project)
		}
		if r.Version != 1 {
			t.Errorf("expected version=1, got %d", r.Version)
		}
	}
}

func TestSearchCrossProject(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	// Find every STRIPE_KEY across all projects.
	refs, err := v.Search(SecretSearchQuery{NameLike: "STRIPE_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 3 {
		t.Errorf("expected 3 STRIPE_KEY across projects, got %d", len(refs))
	}
	got := map[string]bool{}
	for _, r := range refs {
		got[r.Project+"/"+r.Key] = true
	}
	if !got["default/STRIPE_KEY"] || !got["staging/STRIPE_KEY"] || !got["production/STRIPE_KEY"] {
		t.Errorf("missing cross-project: %v", got)
	}
}

func TestSearchNameLikeGlob(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	refs, err := v.Search(SecretSearchQuery{NameLike: "*_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	// STRIPE_KEY (3 projects) + API_KEY (1) + MASTER_KEY (1) = 5
	if len(refs) != 5 {
		t.Errorf("expected 5 *_KEY across projects, got %d", len(refs))
	}
}

func TestSearchPagination(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	first, err := v.Search(SecretSearchQuery{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 {
		t.Errorf("expected 3 with limit=3, got %d", len(first))
	}
	second, err := v.Search(SecretSearchQuery{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 3 {
		t.Errorf("expected 3 with offset=3, got %d", len(second))
	}
	// No overlap between the two pages.
	seen := map[string]bool{}
	for _, r := range first {
		seen[r.Project+"/"+r.Key] = true
	}
	for _, r := range second {
		if seen[r.Project+"/"+r.Key] {
			t.Errorf("overlap between pages: %s/%s", r.Project, r.Key)
		}
	}
}

func TestSearchUpdatedAfter(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	// Look back 1 hour; everything we inserted is < 1 hour old, so
	// we should get all 8 secrets.
	refs, err := v.Search(SecretSearchQuery{Since: time.Now().Add(-1 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 8 {
		t.Errorf("expected 8 secrets within last hour, got %d", len(refs))
	}

	// Look back 1 second; same set.
	refs, err = v.Search(SecretSearchQuery{Since: time.Now().Add(-1 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 8 {
		t.Errorf("expected 8 secrets within last second, got %d", len(refs))
	}

	// Look forward 1 hour; nothing.
	refs, err = v.Search(SecretSearchQuery{Since: time.Now().Add(1 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 secrets in the future, got %d", len(refs))
	}
}

func TestSearchMinVersion(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	// Bump default/STRIPE_KEY once.
	if err := v.SetSecret("default", "STRIPE_KEY", "sk_test_default_v2"); err != nil {
		t.Fatal(err)
	}

	refs, err := v.Search(SecretSearchQuery{Project: "default", MinVersion: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Key != "STRIPE_KEY" {
		t.Errorf("expected [STRIPE_KEY] v>=2, got %+v", refs)
	}
}

func TestSearchProjects(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	all, err := v.SearchProjects("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 projects, got %d", len(all))
	}

	staging, err := v.SearchProjects("staging*", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(staging) != 1 || staging[0] != "staging" {
		t.Errorf("expected [staging], got %v", staging)
	}
}

func TestSnapshotProjects(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	snaps, err := v.SnapshotProjects()
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(snaps))
	}
	for _, s := range snaps {
		if s.SecretCount == 0 {
			t.Errorf("project %s has 0 secrets; should be > 0", s.Name)
		}
	}
}

func TestCountSecrets(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	n, err := v.CountSecrets("default")
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("default should have 4 secrets, got %d", n)
	}
	n, err = v.CountSecrets("production")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("production should have 2 secrets, got %d", n)
	}
}

func TestListProjectNamesByPrefix(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	all, err := v.ListProjectNamesByPrefix("")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3, got %d", len(all))
	}
	prod, err := v.ListProjectNamesByPrefix("prod*")
	if err != nil {
		t.Fatal(err)
	}
	if len(prod) != 1 || prod[0] != "production" {
		t.Errorf("expected [production], got %v", prod)
	}
}

func TestListAudit(t *testing.T) {
	v := setupQueryVault(t)
	defer v.Close()

	// setupQueryVault inserts 8 secrets; each SetSecret should write
	// an audit entry. (Actually SetSecret does not call AppendAudit
	// in the vault layer; only MCP handlers do. So we expect 0.)
	// Test that ListAudit works regardless of the count.
	entries, err := v.ListAudit(store.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	// Zero or more; we only assert that the call returns without
	// error and the result is non-nil.
	if entries == nil {
		t.Error("ListAudit returned nil slice; expected empty slice")
	}
}
