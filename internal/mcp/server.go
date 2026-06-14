package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
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
				"Prefer vault_run_with_secrets over vault_get_secret to avoid exposing secret values. " +
				"Use vault_search_secrets and vault_list_secrets_by_prefix to find keys by " +
				"project, prefix, name pattern, or update time -- never iterate values. " +
				"Use vault_secret_history to view a secret's version metadata (no values) and " +
				"vault_rollback_secret to restore an older version (creates a new version; never returns a value).",
		},
	)

	s.registerProjectTools()
	s.registerSecretTools()
	s.registerExecTools()
	s.registerEnvTools()
	s.registerImportEnvTools()
	s.registerStatusTools()
	s.registerGenerateTools()
	s.registerQueryTools()
	s.registerSealTools()
	s.registerVersionTools()
	s.registerResources()
	s.registerPrompts()

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
