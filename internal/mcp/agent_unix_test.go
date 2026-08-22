//go:build unix

package mcp

import (
	"os"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func TestAgentBackedMCPReadsWithoutKEK(t *testing.T) {
	dir, stop := startMCPTestAgent(t)
	defer stop()

	client, err := agent.Dial(dir, 2*time.Second)
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	srv := NewAgentMCPServer(dir, client, DefaultPolicy())
	t.Cleanup(srv.Close)

	ctx, cs := connectReopeningClient(t, srv)

	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "vault_get_secret",
		Arguments: map[string]any{"key": "API_KEY"},
	})
	if err != nil {
		t.Fatalf("get via agent: %v", err)
	}
	if res.IsError {
		t.Fatalf("get via agent error: %s", toolText(t, res))
	}
	if !strings.Contains(toolText(t, res), "sk_live") {
		t.Fatalf("get via agent missing value: %s", toolText(t, res))
	}

	list, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "vault_list_secrets",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(toolText(t, list), "API_KEY") {
		t.Fatalf("list missing API_KEY: %s", toolText(t, list))
	}

	_, _, setErr := srv.handleSetSecret(ctx, nil, setSecretInput{Key: "NEW", Value: "x"})
	if setErr == nil || !strings.Contains(setErr.Error(), "read-only") {
		t.Fatalf("set via agent-backed mcp: %v, want read-only", setErr)
	}
}

func toolText(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}

func startMCPTestAgent(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tvm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(dir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "API_KEY", "sk_live"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "DB_URL", "postgres://x"); err != nil {
		t.Fatal(err)
	}
	kek, err := v.KEK()
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Start(agent.Options{
			Dir: dir, KEK: kek, Project: "default", Idle: time.Minute,
			OnReady: func(sock string, _ int) { ready <- sock },
		})
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("agent start: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not become ready")
	}
	stop := func() {
		c, derr := agent.Dial(dir, time.Second)
		if derr == nil {
			_ = c.Stop()
		}
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
	}
	return dir, stop
}
