package mcp

import (
	"context"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

const reopenPassphrase = "test-passphrase"

// newReopeningTestServer creates a vault on disk, seeds it, extracts the KEK,
// and closes the vault so bbolt's lock is released. It returns a
// reopen-per-request MCP server (the production `tvault mcp` mode) and the
// vault dir. Unlike newScratchServer, NO vault is held open — that is the whole
// point of this mode.
func newReopeningTestServer(t *testing.T) (*VaultMCPServer, string) {
	t.Helper()

	dir := t.TempDir()
	v, err := vault.Create(dir, reopenPassphrase)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	if err := v.SetSecret("default", "DB_URL", "postgres://localhost/test"); err != nil {
		t.Fatalf("set DB_URL: %v", err)
	}
	if err := v.SetSecret("default", "API_KEY", "sk-secret-value-123"); err != nil {
		t.Fatalf("set API_KEY: %v", err)
	}
	kek, err := v.KEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	if cerr := v.Close(); cerr != nil {
		t.Fatalf("close vault: %v", cerr)
	}

	srv := NewReopeningVaultMCPServer(dir, kek, DefaultPolicy())
	t.Cleanup(srv.Close)
	return srv, dir
}

// assertVaultFree proves bbolt's lock is free right now: a direct vault.Open
// must succeed. If the reopening server were holding the database open (the old
// bug), this would fail with ErrVaultBusy.
func assertVaultFree(t *testing.T, dir, when string) {
	t.Helper()
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatalf("vault.Open %s: got %v, want success (db must be free for the CLI)", when, err)
	}
	if cerr := v.Close(); cerr != nil {
		t.Fatalf("close probe vault %s: %v", when, cerr)
	}
}

func connectReopeningClient(t *testing.T, srv *VaultMCPServer) (context.Context, *sdkmcp.ClientSession) {
	t.Helper()
	ctx := context.Background()
	t1, t2 := sdkmcp.NewInMemoryTransports()
	if _, err := srv.server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return ctx, cs
}

func listSecretsText(t *testing.T, ctx context.Context, cs *sdkmcp.ClientSession) string {
	t.Helper()
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "vault_list_secrets",
		Arguments: map[string]any{"project": "default"},
	})
	if err != nil {
		t.Fatalf("call vault_list_secrets: %v", err)
	}
	if res.IsError {
		t.Fatalf("vault_list_secrets returned error: %s", res.Content[0].(*sdkmcp.TextContent).Text)
	}
	return res.Content[0].(*sdkmcp.TextContent).Text
}

// TestReopeningServer_DoesNotHoldLock is the acceptance test for PROPOSAL #1a:
// a running `tvault mcp` must not block the CLI. It proves the database is free
// both before and after a request, and that tool calls still work end-to-end.
func TestReopeningServer_DoesNotHoldLock(t *testing.T) {
	srv, dir := newReopeningTestServer(t)
	ctx, cs := connectReopeningClient(t, srv)

	// Idle, connected server holds no lock.
	assertVaultFree(t, dir, "after connect")

	// A tool call reopens+unlocks the vault and returns real data.
	text := listSecretsText(t, ctx, cs)
	for _, want := range []string{"DB_URL", "API_KEY"} {
		if !strings.Contains(text, want) {
			t.Errorf("vault_list_secrets missing %q in: %s", want, text)
		}
	}

	// The lock is released again once the request completes.
	assertVaultFree(t, dir, "after tool call")
}

// TestReopeningServer_ReopensEachRequest proves the server truly reopens the
// vault per request (not a stale cached snapshot): a secret written directly to
// the database between requests is visible to the next tool call. This exercises
// both halves of the fix — coexistence (the direct write succeeds while the
// server is connected) and freshness (the server sees it).
func TestReopeningServer_ReopensEachRequest(t *testing.T) {
	srv, dir := newReopeningTestServer(t)
	ctx, cs := connectReopeningClient(t, srv)

	// Direct write while the MCP server is connected — must succeed (no lock
	// contention) and must be picked up by the next request.
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatalf("direct open: %v", err)
	}
	if uerr := v.Unlock(reopenPassphrase); uerr != nil {
		t.Fatalf("unlock: %v", uerr)
	}
	if serr := v.SetSecret("default", "FRESH_KEY", "added-out-of-band"); serr != nil {
		t.Fatalf("set FRESH_KEY: %v", serr)
	}
	if cerr := v.Close(); cerr != nil {
		t.Fatalf("close direct: %v", cerr)
	}

	text := listSecretsText(t, ctx, cs)
	if !strings.Contains(text, "FRESH_KEY") {
		t.Errorf("reopening server did not see out-of-band write; got: %s", text)
	}
}

// TestReopeningServer_CloseZeroesKEK verifies Close zeros the cached KEK and
// that subsequent vault-touching requests fail closed rather than using a
// dangling key.
func TestReopeningServer_CloseZeroesKEK(t *testing.T) {
	srv, _ := newReopeningTestServer(t)
	ctx, cs := connectReopeningClient(t, srv)

	srv.Close()

	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "vault_list_secrets",
		Arguments: map[string]any{"project": "default"},
	})
	// The SDK surfaces a handler error either as a transport error or as an
	// IsError result; accept either, but it must not succeed.
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("expected vault_list_secrets to fail after Close, but it succeeded")
	}
}
