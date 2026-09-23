package mcp

import (
	"context"
	"errors"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// A failing beforeDestructive hook (e.g. the CLI's safety snapshot) must abort
// MCP deletes of both secrets and projects, leaving the data intact.
func TestBeforeDestructiveHookAbortsMCPDeletes(t *testing.T) {
	v, err := vault.Create(t.TempDir(), "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.SetSecret("default", "KEEP", "x"); err != nil {
		t.Fatal(err)
	}
	policy := DefaultPolicy()
	policy.AccessMode = "read-write"
	srv := NewVaultMCPServer(v, policy)
	var reasons []string
	srv.SetBeforeDestructive(func(_ *vault.Vault, reason string) error {
		reasons = append(reasons, reason)
		return errors.New("backup disk full")
	})

	ctx := context.Background()
	t1, t2 := sdkmcp.NewInMemoryTransports()
	if _, err := srv.server.Connect(ctx, t1, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	for _, call := range []sdkmcp.CallToolParams{
		{Name: "vault_delete_secret", Arguments: map[string]any{"key": "KEEP"}},
		{Name: "vault_delete_project", Arguments: map[string]any{"name": "default"}},
	} {
		res, err := cs.CallTool(ctx, &call)
		if err == nil && (res == nil || !res.IsError) {
			t.Fatalf("%s succeeded despite the failing guard", call.Name)
		}
	}
	if got, err := v.GetSecret("default", "KEEP"); err != nil || got != "x" {
		t.Fatalf("data changed despite aborted deletes: %q %v", got, err)
	}
	if len(reasons) != 2 || reasons[0] != "pre-delete" || reasons[1] != "pre-delete-project" {
		t.Fatalf("guard reasons = %v", reasons)
	}
}
