package cmd

import (
	"path/filepath"

	tvmcp "github.com/abdul-hamid-achik/tinyvault/internal/mcp"

	"github.com/spf13/cobra"
)

var mcpServerCmd = &cobra.Command{
	Use:   "mcp-server",
	Short: "Start TinyVault as an MCP server (stdio)",
	Long: `Start TinyVault as a Model Context Protocol server for AI agent integration.
Communicates over stdin/stdout using JSON-RPC.

Configure in .claude/settings.local.json:
  {
    "mcpServers": {
      "tvault": {
        "command": "tvault",
        "args": ["mcp-server"]
      }
    }
  }`,
	Hidden: true,
	RunE:   runMCPServer,
}

func init() {
	rootCmd.AddCommand(mcpServerCmd)
}

func runMCPServer(cmd *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	policyPath := filepath.Join(getVaultDir(), "mcp-policy.yaml")
	policy, _ := tvmcp.LoadPolicy(policyPath) //nolint:errcheck // falls back to default policy below
	if policy == nil {
		policy = tvmcp.DefaultPolicy()
	}

	srv := tvmcp.NewVaultMCPServer(v, policy)
	return srv.Run(cmd.Context())
}
