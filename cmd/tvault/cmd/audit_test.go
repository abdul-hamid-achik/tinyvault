package cmd

import (
	"encoding/json"
	"strings"
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

func setupAuditedVault(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	v, err := ivault.Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v.Close()

	oldDir, oldProject := vaultDir, projectName
	oldFromFile, oldFromEnv, oldKey, oldStdin := setFromFile, setFromEnv, setKey, setStdin
	t.Cleanup(func() {
		vaultDir, projectName = oldDir, oldProject
		setFromFile, setFromEnv, setKey, setStdin = oldFromFile, oldFromEnv, oldKey, oldStdin
		auditLimit, auditSince, auditUntil = 100, "", ""
		auditAction, auditResourceType = "", ""
		jsonOutput = false
	})
	vaultDir, projectName = dir, ""
	setFromFile, setFromEnv, setKey, setStdin = "", "", "", false
	auditLimit = 100
	t.Setenv("TVAULT_PASSPHRASE", "test-passphrase")

	if err := runSet(nil, []string{"API_KEY", "sk_test_never_print_this"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := runGet(nil, []string{"API_KEY"}); err != nil {
		t.Fatalf("get: %v", err)
	}
	return dir
}

func TestAuditListsCLIMutations(t *testing.T) {
	setupAuditedVault(t)

	out := string(captureStdout(t, func() {
		if err := runAudit(nil, nil); err != nil {
			t.Fatalf("runAudit: %v", err)
		}
	}))
	if !strings.Contains(out, "secret.write") {
		t.Errorf("audit output missing secret.write:\n%s", out)
	}
	if !strings.Contains(out, "secret.read") {
		t.Errorf("audit output missing secret.read:\n%s", out)
	}
	if !strings.Contains(out, "API_KEY") {
		t.Errorf("audit output missing resource name API_KEY:\n%s", out)
	}
	if strings.Contains(out, "sk_test_never_print_this") {
		t.Error("audit output leaked the secret value")
	}
}

func TestAuditActionFilter(t *testing.T) {
	setupAuditedVault(t)
	auditAction = "secret.read"

	out := string(captureStdout(t, func() {
		if err := runAudit(nil, nil); err != nil {
			t.Fatalf("runAudit: %v", err)
		}
	}))
	if !strings.Contains(out, "secret.read") {
		t.Errorf("filtered audit missing secret.read:\n%s", out)
	}
	if strings.Contains(out, "secret.write") {
		t.Errorf("filtered audit still contains secret.write:\n%s", out)
	}
}

func TestAuditJSON(t *testing.T) {
	setupAuditedVault(t)
	jsonOutput = true

	raw := captureStdout(t, func() {
		if err := runAudit(nil, nil); err != nil {
			t.Fatalf("runAudit: %v", err)
		}
	})
	var doc struct {
		Count   int                 `json:"count"`
		Entries []*store.AuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, raw)
	}
	if doc.Count == 0 || len(doc.Entries) == 0 {
		t.Fatalf("json audit empty: %+v", doc)
	}
	got := map[string]bool{}
	for _, e := range doc.Entries {
		got[e.Action] = true
	}
	if !got["secret.write"] || !got["secret.read"] {
		t.Errorf("json audit missing expected actions: %v", keysOf(got))
	}
	if strings.Contains(string(raw), "sk_test_never_print_this") {
		t.Error("json audit leaked the secret value")
	}
}

func TestAuditLockFree(t *testing.T) {
	setupAuditedVault(t)
	t.Setenv("TVAULT_PASSPHRASE", "")

	out := string(captureStdout(t, func() {
		if err := runAudit(nil, nil); err != nil {
			t.Fatalf("runAudit on locked vault: %v", err)
		}
	}))
	if !strings.Contains(out, "secret.write") {
		t.Errorf("lock-free audit missing entries:\n%s", out)
	}
}

func TestAuditInvalidSince(t *testing.T) {
	auditLimit = 100
	auditSince = "not-a-timestamp"
	t.Cleanup(func() { auditSince = "" })
	if err := runAudit(nil, nil); err == nil {
		t.Fatal("expected error for invalid --since")
	}
}

func TestAuditInvalidUntil(t *testing.T) {
	auditLimit = 100
	auditUntil = "not-a-timestamp"
	t.Cleanup(func() { auditUntil = "" })
	if err := runAudit(nil, nil); err == nil {
		t.Fatal("expected error for invalid --until")
	}
}

func TestAuditRejectsOutOfRangeLimit(t *testing.T) {
	auditLimit = 0
	if err := runAudit(nil, nil); err == nil {
		t.Fatal("expected error for --limit 0")
	}
	auditLimit = 1001
	t.Cleanup(func() { auditLimit = 100 })
	if err := runAudit(nil, nil); err == nil {
		t.Fatal("expected error for --limit 1001")
	}
}

func TestAuditEmpty(t *testing.T) {
	dir := t.TempDir()
	v, err := ivault.Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v.Close()
	oldDir := vaultDir
	t.Cleanup(func() { vaultDir = oldDir })
	vaultDir = dir
	auditLimit = 100

	out := string(captureStdout(t, func() {
		if err := runAudit(nil, nil); err != nil {
			t.Fatalf("runAudit empty: %v", err)
		}
	}))
	if !strings.Contains(out, "(no audit entries)") {
		t.Errorf("empty audit: got %q", out)
	}
}

func TestStudioCommandsRemoved(t *testing.T) {
	names := map[string]bool{}
	for _, c := range rootCmd.Commands() {
		names[c.Name()] = true
		for _, a := range c.Aliases {
			names[a] = true
		}
	}
	for _, name := range []string{"studio", "browse", "ui"} {
		if names[name] {
			t.Errorf("removed command %q is still registered", name)
		}
	}
	if !names["audit"] {
		t.Fatal("audit command missing")
	}
}
