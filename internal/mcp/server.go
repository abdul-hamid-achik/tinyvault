package mcp

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// VaultMCPServer wraps a vault and exposes it as an MCP server.
//
// It runs in one of two modes:
//
//   - Held-open (NewVaultMCPServer): the server keeps a single unlocked
//     *vault.Vault for its lifetime. Used by tests, which drive handlers
//     directly against an in-memory temp vault.
//   - Reopen-per-request (NewReopeningVaultMCPServer): the production `tvault
//     mcp` mode. The server caches only the KEK and reopens+unlocks the vault
//     for the duration of each request via receiving middleware, then closes
//     it. This mirrors `tvault agent`: bbolt is single-writer, so holding the
//     database open for the server's lifetime would block every other tvault
//     process (set/get/run/import). Reopening per request keeps the file free
//     for direct CLI access between requests.
type VaultMCPServer struct {
	server *sdkmcp.Server
	vault  *vault.Vault
	policy *AccessPolicy

	// Reopen-per-request state. When reopen is true, vault is non-nil only for
	// the duration of an in-flight request (set by vaultMiddleware) and the
	// dir/kek are used to open+unlock it. vaultMu serializes those opens so the
	// server never holds two bbolt opens at once.
	reopen  bool
	dir     string
	kek     []byte
	vaultMu sync.Mutex
	reads   atomic.Int64
}

func (s *VaultMCPServer) consumeValueRead() bool {
	limit := int64(s.policy.MaxReadsPerSession)
	if limit <= 0 {
		return true
	}
	for {
		current := s.reads.Load()
		if current >= limit {
			return false
		}
		if s.reads.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// NewVaultMCPServer creates a held-open MCP server backed by the given unlocked
// vault and policy. The vault stays open for the server's lifetime.
func NewVaultMCPServer(v *vault.Vault, policy *AccessPolicy) *VaultMCPServer {
	s := newVaultMCPServer(policy)
	s.vault = v
	return s
}

// NewReopeningVaultMCPServer creates an MCP server that does NOT hold the vault
// open. It caches the KEK and reopens+unlocks the vault per request under a
// mutex, releasing bbolt's lock between requests so the CLI and other tvault
// processes keep working. The server copies kek; the caller still owns its own
// copy. Call Close to zero the cached KEK on shutdown.
func NewReopeningVaultMCPServer(dir string, kek []byte, policy *AccessPolicy) *VaultMCPServer {
	s := newVaultMCPServer(policy)
	s.reopen = true
	s.dir = dir
	s.kek = make([]byte, len(kek))
	copy(s.kek, kek)
	s.server.AddReceivingMiddleware(s.vaultMiddleware)
	return s
}

// newVaultMCPServer builds the SDK server and registers all tools/resources/
// prompts. Both constructors share it.
func newVaultMCPServer(policy *AccessPolicy) *VaultMCPServer {
	if policy == nil {
		policy = DefaultPolicy()
	}

	s := &VaultMCPServer{
		policy: policy,
	}

	s.server = sdkmcp.NewServer(
		&sdkmcp.Implementation{
			Name:    "tinyvault",
			Version: "0.17.0",
		},
		&sdkmcp.ServerOptions{
			Instructions: "TinyVault provides secure local secret management. " +
				"Prefer vault_run_with_secrets over vault_get_secret to avoid exposing secret values. " +
				"Use vault_search_secrets and vault_list_secrets_by_prefix to find keys by " +
				"project, prefix, name pattern, or update time -- never iterate values. " +
				"Use vault_secret_history to view a secret's version metadata (no values) and " +
				"vault_rollback_secret to restore an older version (creates a new version; never returns a value). " +
				"For a full machine-readable capability manifest, the host can run `tvault docs features` (CLI); " +
				"`tvault help agent --json` documents the recommended discover-search-use workflow.",
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
	s.registerNavigationTools()
	s.registerSecretMetaTools()
	s.registerSharingTools()
	s.registerDotenvTools()
	s.registerIdentityTools()
	s.registerEnvGroupTools()
	s.registerResources()
	s.registerPrompts()

	return s
}

// Run starts the MCP server on the stdio transport.
func (s *VaultMCPServer) Run(ctx context.Context) error {
	return s.server.Run(ctx, &sdkmcp.StdioTransport{})
}

// Close zeros the cached KEK. Safe to call on a held-open server (no-op).
func (s *VaultMCPServer) Close() {
	s.vaultMu.Lock()
	defer s.vaultMu.Unlock()
	if s.kek != nil {
		crypto.ZeroBytes(s.kek)
		s.kek = nil
	}
}

// vaultMiddleware reopens and unlocks the vault for the duration of each
// vault-touching request, then closes it — serialized so the server never holds
// two bbolt opens at once and the database stays free for direct CLI access
// between requests. It mirrors the agent's withVault model. Methods that don't
// touch the vault (initialize, tools/list, ping, notifications, prompts/get,
// …) pass straight through, so a transient lock contention never blocks a
// handshake or a notification.
func (s *VaultMCPServer) vaultMiddleware(next sdkmcp.MethodHandler) sdkmcp.MethodHandler {
	return func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
		if !methodNeedsVault(method) {
			return next(ctx, method, req)
		}

		s.vaultMu.Lock()
		defer s.vaultMu.Unlock()

		if s.kek == nil {
			return nil, fmt.Errorf("mcp server is shutting down")
		}
		v, err := vault.Open(s.dir)
		if err != nil {
			return nil, err
		}
		defer v.Close()
		if err := v.UnlockWithKEK(s.kek); err != nil {
			return nil, fmt.Errorf("unlock: %w (passphrase rotated? restart 'tvault mcp')", err)
		}

		s.vault = v
		defer func() { s.vault = nil }()
		return next(ctx, method, req)
	}
}

// methodNeedsVault reports whether an incoming MCP method dispatches to a
// handler that touches the vault. tools/call covers every tool (the SDK routes
// all tool invocations through it); resources/read covers the resource
// handlers. Everything else (tools/list, resources/list, prompts/*,
// initialize, ping, notifications) is served from static metadata.
func methodNeedsVault(method string) bool {
	switch method {
	case "tools/call", "resources/read":
		return true
	default:
		return false
	}
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
