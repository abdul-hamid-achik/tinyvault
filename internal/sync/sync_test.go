package sync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSource is an in-memory Source for tests. It satisfies the
// Source interface without needing a real bbolt vault.
type fakeSource struct {
	secrets map[string]map[string]string // project -> key -> value
}

func newFake() *fakeSource {
	return &fakeSource{secrets: map[string]map[string]string{}}
}

func (f *fakeSource) ensure(project string) {
	if _, ok := f.secrets[project]; !ok {
		f.secrets[project] = map[string]string{}
	}
}

func (f *fakeSource) GetAllSecrets(project string) (map[string]string, error) {
	f.ensure(project)
	out := make(map[string]string, len(f.secrets[project]))
	for k, v := range f.secrets[project] {
		out[k] = v
	}
	return out, nil
}

func (f *fakeSource) SetSecret(project, key, value string) error {
	f.ensure(project)
	f.secrets[project][key] = value
	return nil
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPullCreatesFile(t *testing.T) {
	src := newFake()
	_ = src.SetSecret("default", "FOO", "foo-value")
	_ = src.SetSecret("default", "BAR", "bar-value")

	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	res, err := Sync(src, "default", path, Pull, false)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !res.EnvCreated {
		t.Errorf("expected EnvCreated=true")
	}
	if len(res.Created) != 2 {
		t.Errorf("expected 2 created, got %d", len(res.Created))
	}

	body := readFile(t, path)
	for _, want := range []string{"FOO=foo-value", "BAR=bar-value"} {
		if !strings.Contains(body, want) {
			t.Errorf("file missing %q\n%s", want, body)
		}
	}
}

func TestPullPreservesUnrelatedEnvKeys(t *testing.T) {
	src := newFake()
	_ = src.SetSecret("default", "FOO", "foo-value")
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "UNRELATED=kept\nFOO=old-value\n")

	res, err := Sync(src, "default", path, Pull, false)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if !containsAll(res.Updated, []string{"FOO"}) {
		t.Errorf("FOO should be Updated, got %+v", res.Updated)
	}
	// UNRELATED was not in the vault, so pull did not touch it. It
	// should still be in the file.
	body := readFile(t, path)
	if !strings.Contains(body, "UNRELATED=kept") {
		t.Errorf("UNRELATED was wiped by pull: %s", body)
	}
	if !strings.Contains(body, "FOO=foo-value") {
		t.Errorf("FOO not updated: %s", body)
	}
}

func TestPushWritesToVault(t *testing.T) {
	src := newFake()
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "A=1\nB=2\n")

	res, err := Sync(src, "default", path, Push, false)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Created) != 2 {
		t.Errorf("expected 2 created, got %d", len(res.Created))
	}
	gotA, _ := src.GetAllSecrets("default")
	if gotA["A"] != "1" || gotA["B"] != "2" {
		t.Errorf("vault not updated: %+v", gotA)
	}
}

func TestPushSkipsExistingWithoutOverwrite(t *testing.T) {
	src := newFake()
	_ = src.SetSecret("default", "A", "vault-value")
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "A=env-value\n")

	res, err := Sync(src, "default", path, Push, false)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !containsAll(res.Skipped, []string{"A"}) {
		t.Errorf("A should be Skipped, got %+v", res.Skipped)
	}
	got, _ := src.GetAllSecrets("default")
	if got["A"] != "vault-value" {
		t.Errorf("vault was overwritten without --overwrite: %s", got["A"])
	}
}

func TestPushOverwritesWhenFlagged(t *testing.T) {
	src := newFake()
	_ = src.SetSecret("default", "A", "vault-value")
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "A=env-value\n")

	res, err := Sync(src, "default", path, Push, true)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !containsAll(res.Updated, []string{"A"}) {
		t.Errorf("A should be Updated, got %+v", res.Updated)
	}
	got, _ := src.GetAllSecrets("default")
	if got["A"] != "env-value" {
		t.Errorf("vault was not overwritten with --overwrite: %s", got["A"])
	}
}

func TestMirrorReportsConflicts(t *testing.T) {
	src := newFake()
	_ = src.SetSecret("default", "A", "vault-A")
	_ = src.SetSecret("default", "B", "vault-B")
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "A=env-A\nB=env-B\nC=env-C\n")

	res, err := Sync(src, "default", path, Mirror, false)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Conflicts) != 2 {
		t.Errorf("expected 2 conflicts, got %d: %+v", len(res.Conflicts), res.Conflicts)
	}
	if !containsAll(res.Skipped, []string{"A", "B"}) {
		t.Errorf("A and B should be Skipped on conflict, got %+v", res.Skipped)
	}
	if !containsAll(res.Created, []string{"C"}) {
		t.Errorf("C should be Created (env-only), got %+v", res.Created)
	}
}

func TestMirrorWithOverwriteResolvesConflicts(t *testing.T) {
	src := newFake()
	_ = src.SetSecret("default", "A", "vault-A")
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "A=env-wins\n")

	res, err := Sync(src, "default", path, Mirror, true)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(res.Conflicts))
	}
	if res.Conflicts[0].Resolution != "kept-env" {
		t.Errorf("expected kept-env resolution, got %q", res.Conflicts[0].Resolution)
	}
	if !containsAll(res.Updated, []string{"A"}) {
		t.Errorf("A should be Updated when --overwrite, got %+v", res.Updated)
	}
	got, _ := src.GetAllSecrets("default")
	if got["A"] != "env-wins" {
		t.Errorf("vault should now hold env value, got %q", got["A"])
	}
}

func TestMirrorVaultOnlyKeyIsPulledToEnv(t *testing.T) {
	src := newFake()
	_ = src.SetSecret("default", "VAULT_ONLY", "from-vault")
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "ENV_ONLY=from-env\n")

	res, err := Sync(src, "default", path, Mirror, true)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !containsAll(res.Created, []string{"VAULT_ONLY", "ENV_ONLY"}) {
		t.Errorf("both keys should be Created, got %+v", res.Created)
	}
	got, _ := src.GetAllSecrets("default")
	if got["VAULT_ONLY"] != "from-vault" || got["ENV_ONLY"] != "from-env" {
		t.Errorf("both should now be in vault, got %+v", got)
	}
}

func TestParseDirection(t *testing.T) {
	tests := []struct {
		in      string
		want    Direction
		wantErr bool
	}{
		{"pull", Pull, false},
		{"PULL", Pull, false},
		{"push", Push, false},
		{"mirror", Mirror, false},
		{"vault->env", Pull, false},
		{"env->vault", Push, false},
		{"two-way", Mirror, false},
		{"unknown", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDirection(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func containsAll(haystack []string, needles []string) bool {
	set := make(map[string]struct{}, len(haystack))
	for _, s := range haystack {
		set[s] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
}
