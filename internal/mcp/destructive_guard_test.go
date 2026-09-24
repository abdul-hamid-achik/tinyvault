package mcp

import (
	"context"
	"errors"
	"io"
	"os"
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

// A successful destructive MCP call (guard hook included) must write nothing
// to process stdout: under `tvault mcp`, stdout is the JSON-RPC channel and
// any stray print corrupts the protocol framing.
func TestMCPDeleteWritesNothingToStdout(t *testing.T) {
	v, err := vault.Create(t.TempDir(), "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.SetSecret("default", "GONE", "x"); err != nil {
		t.Fatal(err)
	}
	policy := DefaultPolicy()
	policy.AccessMode = "read-write"
	srv := NewVaultMCPServer(v, policy)
	srv.SetBeforeDestructive(func(_ *vault.Vault, _ string) error { return nil })

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

	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "vault_delete_secret",
		Arguments: map[string]any{"key": "GONE"},
	})
	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	if len(out) != 0 {
		t.Fatalf("destructive call wrote to stdout: %q", out)
	}
	if err != nil || res == nil || res.IsError {
		t.Fatalf("delete failed: %v", err)
	}
	if _, err := v.GetSecret("default", "GONE"); !errors.Is(err, vault.ErrSecretNotFound) {
		t.Fatalf("secret survived the delete: %v", err)
	}
}
