package cmd

import (
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// TestCLIMutationsAreAudited verifies that set/get/delete and project
// create/delete from the CLI now write audit entries (previously only the
// MCP server logged, so CLI activity was invisible in the audit log).
func TestCLIMutationsAreAudited(t *testing.T) {
	dir := t.TempDir()
	v, err := ivault.Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v.Close()

	// Save + restore the package-level command state we touch.
	old := struct {
		vaultDir, projectName, setFromFile, setFromEnv, setKey string
		setStdin, deleteForce, projectDeleteForce              bool
	}{vaultDir, projectName, setFromFile, setFromEnv, setKey, setStdin, deleteForce, projectDeleteForce}
	t.Cleanup(func() {
		vaultDir, projectName = old.vaultDir, old.projectName
		setFromFile, setFromEnv, setKey = old.setFromFile, old.setFromEnv, old.setKey
		setStdin, deleteForce, projectDeleteForce = old.setStdin, old.deleteForce, old.projectDeleteForce
	})
	vaultDir, projectName = dir, ""
	setFromFile, setFromEnv, setKey, setStdin = "", "", "", false
	deleteForce, projectDeleteForce = true, true
	t.Setenv("TVAULT_PASSPHRASE", "test-passphrase")

	if err := runProjectsCreate(nil, []string{"webapp"}); err != nil {
		t.Fatalf("projects create: %v", err)
	}
	projectName = "webapp"
	if err := runSet(nil, []string{"API_KEY", "sk_test_123"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := runGet(nil, []string{"API_KEY"}); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := runDelete(nil, []string{"API_KEY"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	projectName = ""
	if err := runProjectsDelete(nil, []string{"webapp"}); err != nil {
		t.Fatalf("projects delete: %v", err)
	}

	v2, err := ivault.Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer v2.Close()
	entries, err := v2.ListAudit(store.AuditFilter{})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Action] = true
	}
	for _, want := range []string{"secret.write", "secret.read", "secret.delete", "project.create", "project.delete"} {
		if !got[want] {
			t.Errorf("audit log missing action %q; got %v", want, keysOf(got))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
