package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	tvmcp "github.com/abdul-hamid-achik/tinyvault/internal/mcp"
)

var mcpConnect string

var mcpServerCmd = &cobra.Command{
	Use:     "mcp",
	Aliases: []string{"mcp-server"},
	Short:   "Start TinyVault as an MCP server (stdio)",
	Long: `Start TinyVault as a Model Context Protocol server for AI agent integration.
Communicates over stdin/stdout using JSON-RPC.

If a local tvault agent is running, mcp uses it for secret reads and does
not need TVAULT_PASSPHRASE. Writes still need the passphrase (the agent is
read-only). --connect unix://PATH pins the agent socket; --connect none
(or --no-agent) requires a passphrase.

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
	mcpServerCmd.Flags().StringVar(&mcpConnect, "connect", "auto",
		"Agent socket: auto, none, or unix://PATH")
}

func runMCPServer(cmd *cobra.Command, _ []string) error {
	mode, socket, err := parseMCPConnect(mcpConnect)
	if err != nil {
		return err
	}
	if agentDisabled() {
		mode = "none"
	}

	dir := getVaultDir()
	policyPath := filepath.Join(dir, "mcp-policy.yaml")
	policy, err := tvmcp.LoadPolicy(policyPath)
	if err != nil {
		return fmt.Errorf("load MCP access policy %s: %w", policyPath, err)
	}
	if policy == nil {
		policy = tvmcp.SafeDefaultPolicy()
	}

	kek, ac, err := resolveMCPBackend(mode, socket, dir)
	if err != nil {
		return err
	}
	if len(kek) > 0 {
		defer crypto.ZeroBytes(kek)
	}

	tvmcp.SetBuildVersion(Version())
	var srv *tvmcp.VaultMCPServer
	if ac != nil && len(kek) == 0 {
		fmt.Fprintln(os.Stderr, "tvault mcp: using local agent for secret reads (writes need TVAULT_PASSPHRASE)")
		srv = tvmcp.NewAgentMCPServer(dir, ac, policy)
	} else {
		srv = tvmcp.NewReopeningVaultMCPServer(dir, kek, policy)
	}
	defer srv.Close()
	return srv.Run(cmd.Context())
}

func parseMCPConnect(s string) (mode, socket string, err error) {
	s = strings.TrimSpace(s)
	switch s {
	case "", "auto":
		return "auto", "", nil
	case "none":
		return "none", "", nil
	}
	path, ok := strings.CutPrefix(s, "unix://")
	if !ok || path == "" {
		return "", "", fmt.Errorf("--connect must be auto, none, or unix://PATH")
	}
	return "unix", path, nil
}

func mcpHasPassphrase() bool {
	cfg, err := loadConfig()
	if err != nil {
		return strings.TrimSpace(os.Getenv("TVAULT_PASSPHRASE")) != ""
	}
	pass, err := passphraseFromEnvOrFile(cfg)
	return err == nil && pass != ""
}

func dialMCPAgent(dir, socket string) (*agent.Client, error) {
	var (
		c   *agent.Client
		err error
	)
	if socket == "" {
		c, err = agent.Dial(dir, 3*time.Second)
	} else {
		c, err = agent.DialSocket(socket, 3*time.Second)
	}
	if err != nil {
		return nil, err
	}
	if tok := strings.TrimSpace(os.Getenv("TVAULT_AGENT_TOKEN")); tok != "" {
		c = c.WithToken(tok)
	}
	if _, err := c.Status(); err != nil {
		return nil, err
	}
	return c, nil
}

func resolveMCPBackend(mode, socket, dir string) (kek []byte, ac *agent.Client, err error) {
	if mcpHasPassphrase() {
		v, uerr := openAndUnlockVault()
		if uerr != nil {
			return nil, nil, uerr
		}
		k, kerr := v.KEK()
		_ = v.Close()
		if kerr != nil {
			return nil, nil, kerr
		}
		return k, nil, nil
	}

	switch mode {
	case "none":
		v, uerr := openAndUnlockVault()
		if uerr != nil {
			return nil, nil, uerr
		}
		k, kerr := v.KEK()
		_ = v.Close()
		if kerr != nil {
			return nil, nil, kerr
		}
		return k, nil, nil
	case "unix":
		c, derr := dialMCPAgent(dir, socket)
		if derr != nil {
			return nil, nil, fmt.Errorf("mcp --connect: %w", derr)
		}
		return nil, c, nil
	default: // auto
		if c, derr := dialMCPAgent(dir, ""); derr == nil {
			return nil, c, nil
		}
		v, uerr := openAndUnlockVault()
		if uerr != nil {
			return nil, nil, uerr
		}
		k, kerr := v.KEK()
		_ = v.Close()
		if kerr != nil {
			return nil, nil, kerr
		}
		return k, nil, nil
	}
}
