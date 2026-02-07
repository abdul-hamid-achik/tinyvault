package mcp

import (
	"context"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// VaultMCPServer wraps a vault and exposes it as an MCP server.
type VaultMCPServer struct {
	server *sdkmcp.Server
	vault  *vault.Vault
	policy *AccessPolicy
}

// NewVaultMCPServer creates a new MCP server backed by the given vault and policy.
func NewVaultMCPServer(v *vault.Vault, policy *AccessPolicy) *VaultMCPServer {
	if policy == nil {
		policy = DefaultPolicy()
	}

	s := &VaultMCPServer{
		vault:  v,
		policy: policy,
	}

	s.server = sdkmcp.NewServer(
		&sdkmcp.Implementation{
			Name:    "tinyvault",
			Version: "1.0.0",
		},
		&sdkmcp.ServerOptions{
			Instructions: "TinyVault provides secure local secret management. " +
				"Prefer vault_run_with_secrets over vault_get_secret to avoid exposing secret values.",
		},
	)

	s.registerProjectTools()
	s.registerSecretTools()
	s.registerExecTools()
	s.registerEnvTools()

	return s
}

// Run starts the MCP server on the stdio transport.
func (s *VaultMCPServer) Run(ctx context.Context) error {
	return s.server.Run(ctx, &sdkmcp.StdioTransport{})
}

// resolveProject returns the project name to use, falling back to the
// vault's current project if none is explicitly specified.
func (s *VaultMCPServer) resolveProject(explicit string) string {
	if explicit != "" {
		return explicit
	}
	name, err := s.vault.GetCurrentProject()
	if err != nil || name == "" {
		return "default"
	}
	return name
}
