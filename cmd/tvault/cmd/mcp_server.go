package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	tvmcp "github.com/abdul-hamid-achik/tinyvault/internal/mcp"

	"github.com/spf13/cobra"
)

var mcpServerCmd = &cobra.Command{
	Use:     "mcp",
	Aliases: []string{"mcp-server"},
	Short:   "Start TinyVault as an MCP server (stdio)",
	Long: `Start TinyVault as a Model Context Protocol server for AI agent integration.
Communicates over stdin/stdout using JSON-RPC.

Configure in .claude/settings.local.json:
  {
    "mcpServers": {
      "tvault": {
        "command": "tvault",
        "args": ["mcp"]
      }
    }
  }

The "mcp-server" name still works as an alias for backward compatibility.`,
	RunE: runMCPServer,
}

func init() {
	rootCmd.AddCommand(mcpServerCmd)
}

func runMCPServer(cmd *cobra.Command, _ []string) error {
	// Unlock once to derive + validate the KEK, then close the vault so bbolt's
	// exclusive lock is released. The server reopens the vault per request (see
	// NewReopeningVaultMCPServer), so a long-running `tvault mcp` no longer
	// blocks `tvault set/get/run/import` on the same machine.
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	kek, err := v.KEK()
	_ = v.Close() // release the bbolt lock immediately
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(kek)

	policyPath := filepath.Join(getVaultDir(), "mcp-policy.yaml")
	policy, err := tvmcp.LoadPolicy(policyPath)
	if err != nil {
		return fmt.Errorf("load MCP access policy %s: %w", policyPath, err)
	}
	if policy == nil {
		policy = tvmcp.SafeDefaultPolicy()
	}

	srv := tvmcp.NewReopeningVaultMCPServer(getVaultDir(), kek, policy)
	defer srv.Close()
	return srv.Run(cmd.Context())
}
