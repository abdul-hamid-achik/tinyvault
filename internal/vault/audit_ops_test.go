package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
)

func TestVaultLayerAuditsPrimitives(t *testing.T) {
	v := createTestVault(t)

	if err := v.SetSecret("default", "API_KEY", "sk_never_in_audit"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if _, err := v.GetSecret("default", "API_KEY"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if _, err := v.GetSecretWithMeta("default", "API_KEY", map[string]any{"via": "agent", "peer_uid": 501}); err != nil {
		t.Fatalf("GetSecretWithMeta: %v", err)
	}
	if _, err := v.GetSecretVersionValue("default", "API_KEY", 1); err != nil {
		t.Fatalf("GetSecretVersionValue: %v", err)
	}
	if _, err := v.ListSecretVersions("default", "API_KEY"); err != nil {
		t.Fatalf("ListSecretVersions: %v", err)
	}
	if _, err := v.CreateProject("webapp", ""); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if err := v.SetSecret("webapp", "TOKEN", "tok"); err != nil {
		t.Fatalf("SetSecret webapp: %v", err)
	}
	if err := v.DeleteSecret("webapp", "TOKEN"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if err := v.DeleteProject("webapp"); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}

	entries, err := v.ListAudit(store.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	got := map[string]int{}
	var agentRead bool
	for _, e := range entries {
		got[e.Action]++
		if e.Action == "secret.read" && e.Metadata["via"] == "agent" {
			agentRead = true
			if e.Metadata["peer_uid"] == nil {
				t.Error("agent read missing peer_uid")
			}
		}
	}
	for _, action := range []string{"secret.write", "secret.read", "secret.delete", "project.create", "project.delete"} {
		if got[action] == 0 {
			t.Errorf("missing action %q in %v", action, got)
		}
	}
	if !agentRead {
		t.Error("expected GetSecretWithMeta to record via:agent")
	}

	blob, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "sk_never_in_audit") {
		t.Error("audit log leaked a secret value")
	}
}

func TestCreateDoesNotAuditDefaultProject(t *testing.T) {
	v := createTestVault(t)
	entries, err := v.ListAudit(store.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("fresh vault should have no audit rows, got %d", len(entries))
	}
}

func TestGetAllSecretsAuditsBulkWithoutValues(t *testing.T) {
	v := createTestVault(t)
	if err := v.SetSecret("default", "API_KEY", "sk_bulk_never_logged"); err != nil {
		t.Fatal(err)
	}
	all, err := v.GetAllSecrets("default")
	if err != nil {
		t.Fatal(err)
	}
	if all["API_KEY"] != "sk_bulk_never_logged" {
		t.Fatalf("unexpected value map: %v", all)
	}
	entries, err := v.ListAudit(store.AuditFilter{Action: "secret.read"})
	if err != nil {
		t.Fatal(err)
	}
	var bulk bool
	for _, e := range entries {
		if e.ResourceType == "project" && e.ResourceName == "default" {
			if e.Metadata["bulk"] != true {
				t.Errorf("bulk metadata = %v, want true", e.Metadata["bulk"])
			}
			bulk = true
		}
	}
	if !bulk {
		t.Fatal("GetAllSecrets did not write a project-level secret.read")
	}
	blob, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "sk_bulk_never_logged") {
		t.Error("bulk audit leaked a secret value")
	}
}

func TestFailedGetDoesNotAudit(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.GetSecret("default", "MISSING"); err == nil {
		t.Fatal("expected missing secret error")
	}
	entries, err := v.ListAudit(store.AuditFilter{Action: "secret.read"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("failed get wrote %d audit rows", len(entries))
	}
}

func TestRollbackAuditsWithoutValue(t *testing.T) {
	v := createTestVault(t)
	if err := v.SetSecret("default", "K", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "K", "v2"); err != nil {
		t.Fatal(err)
	}
	newVer, err := v.RollbackSecret("default", "K", 1)
	if err != nil {
		t.Fatalf("RollbackSecret: %v", err)
	}
	entries, err := v.ListAudit(store.AuditFilter{Action: "secret.rollback"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("rollback rows = %d, want 1", len(entries))
	}
	meta := entries[0].Metadata
	if fmt.Sprintf("%v", meta["from_version"]) != "1" {
		t.Errorf("from_version = %v", meta["from_version"])
	}
	if fmt.Sprintf("%v", meta["new_version"]) != fmt.Sprintf("%d", newVer) {
		t.Errorf("new_version = %v, want %d", meta["new_version"], newVer)
	}
	blob, _ := json.Marshal(entries[0])
	if strings.Contains(string(blob), "v1") || strings.Contains(string(blob), "v2") {
		t.Errorf("rollback audit leaked a value: %s", blob)
	}
}
