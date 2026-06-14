package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// versionTestServer builds a server over a vault whose "API_KEY" has 3
// versions, so history/rollback have something to act on.
func versionTestServer(t *testing.T, policy *AccessPolicy) *VaultMCPServer {
	t.Helper()
	v, err := vault.Create(t.TempDir(), "pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	for _, val := range []string{"v1", "v2", "v3"} {
		if err := v.SetSecret("default", "API_KEY", val); err != nil {
			t.Fatalf("set: %v", err)
		}
	}
	if policy == nil {
		policy = DefaultPolicy()
	}
	return NewVaultMCPServer(v, policy)
}

func TestSecretHistoryToolReturnsNoValue(t *testing.T) {
	srv := versionTestServer(t, nil)
	_, out, err := srv.handleSecretHistory(context.Background(), nil, secretHistoryInput{Key: "API_KEY"})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(out.Versions) != 3 {
		t.Fatalf("want 3 versions, got %d", len(out.Versions))
	}
	// No-value guarantee is structural: the serialized output must carry no
	// value/ciphertext field, only version metadata.
	blob, _ := json.Marshal(out)
	for _, banned := range []string{"value", "encrypted", "v1", "v2", "v3"} {
		if strings.Contains(string(blob), banned) {
			t.Errorf("history output leaked %q: %s", banned, blob)
		}
	}
}

func TestRollbackSecretToolGatedByCanWrite(t *testing.T) {
	ro := &AccessPolicy{AccessMode: "read-only", ProjectsAllow: []string{"*"}, SecretsAllow: []string{"*"}}
	srv := versionTestServer(t, ro)
	if _, _, err := srv.handleRollbackSecret(context.Background(), nil, rollbackSecretInput{Key: "API_KEY", ToVersion: 1}); err == nil {
		t.Fatal("rollback under a read-only policy must be rejected")
	}
}

func TestRollbackSecretToolSucceedsNoValue(t *testing.T) {
	srv := versionTestServer(t, nil)
	_, out, err := srv.handleRollbackSecret(context.Background(), nil, rollbackSecretInput{Key: "API_KEY", ToVersion: 1})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !out.RolledBack || out.RolledBackFrom != 1 || out.NewVersion != 4 {
		t.Errorf("unexpected rollback output: %+v", out)
	}
	blob, _ := json.Marshal(out)
	for _, banned := range []string{"value", "v1", "encrypted"} {
		if strings.Contains(string(blob), banned) {
			t.Errorf("rollback output leaked %q: %s", banned, blob)
		}
	}
	// The rollback actually restored v1's value (verify via the vault).
	got, err := srv.vault.GetSecret("default", "API_KEY")
	if err != nil || got != "v1" {
		t.Errorf("after rollback current = %q (err %v), want v1", got, err)
	}

	// An audit entry was recorded with the right action + value-free metadata.
	entries, err := srv.vault.ListAudit(store.AuditFilter{Action: "secret.rollback"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected a secret.rollback audit entry")
	}
	meta := entries[0].Metadata
	if meta["from_version"] == nil || meta["new_version"] == nil {
		t.Errorf("rollback audit metadata missing version numbers: %v", meta)
	}
	auditBlob, _ := json.Marshal(entries[0])
	if strings.Contains(string(auditBlob), "v1") || strings.Contains(string(auditBlob), "value") {
		t.Errorf("rollback audit entry leaked a value: %s", auditBlob)
	}
}

func TestRollbackSecretToolVersionNotFound(t *testing.T) {
	srv := versionTestServer(t, nil)
	if _, _, err := srv.handleRollbackSecret(context.Background(), nil, rollbackSecretInput{Key: "API_KEY", ToVersion: 99}); err == nil {
		t.Fatal("rollback to a nonexistent version must error")
	}
}
