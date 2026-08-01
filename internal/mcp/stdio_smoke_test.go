package mcp

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestStdioHandshake drives the real stdio transport the way an MCP host
// would: it spawns $TVAULT_BIN (the tvault binary, or the npm shim after an
// npm install) and completes an initialize + tools/list + ping round trip
// against a fresh temp vault.
//
// The test is gated on TVAULT_BIN so the regular suite stays hermetic — the
// other server tests use in-memory transports, which never exercise the
// StdioTransport. The npm-publish smoke job runs it against the package it
// just published:
//
//	go test ./internal/mcp -run TestStdioHandshake -count=1
//
// Why a real client instead of a piped one-shot (`printf ... | tvault mcp`)?
// The go-sdk stdio transport drops responses when stdin EOF arrives before
// the handler writes them (upstream, unfixed: modelcontextprotocol/go-sdk
// issue #1061). A real client keeps the conversation open, exactly like MCP
// hosts do, so this test exercises the real host path.
func TestStdioHandshake(t *testing.T) {
	bin := os.Getenv("TVAULT_BIN")
	if bin == "" {
		t.Skip("TVAULT_BIN is not set; set it to the tvault binary or npm shim to run this test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Same environment the npm-publish smoke job provides; TVAULT_PASSPHRASE
	// makes `tvault init` and the server's startup unlock non-interactive.
	env := append(os.Environ(),
		"TVAULT_DIR="+t.TempDir(),
		"TVAULT_PASSPHRASE=smoke-test-passphrase",
	)

	initCmd := exec.CommandContext(ctx, bin, "init")
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("tvault init: %v\n%s", err, out)
	}

	server := exec.CommandContext(ctx, bin, "mcp")
	server.Env = env
	client := mcp.NewClient(&mcp.Implementation{Name: "stdio-smoke", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: server}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cs.Close()

	// Connect performs the initialize handshake; assert the server identity.
	res := cs.InitializeResult()
	if res == nil || res.ServerInfo == nil || res.ServerInfo.Name != "tinyvault" {
		t.Fatalf("unexpected initialize result: %+v", res)
	}
	if res.ServerInfo.Version == "" {
		t.Fatal("initialize result has empty server version")
	}

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(tools.Tools) < 10 {
		t.Fatalf("tools/list returned %d tools, want >= 10", len(tools.Tools))
	}

	if err := cs.Ping(ctx, nil); err != nil {
		t.Fatalf("ping: %v", err)
	}
}
