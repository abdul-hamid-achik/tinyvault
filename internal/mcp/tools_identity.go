package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/identity"
)

// Identity tools. They manage the X25519 key files used by the recipient
// layer and return ONLY public recipient strings (tvault1…) — never the
// private key (tvault-key1…).

// --- vault_identity_new ---

type identityNewInput struct {
	Name string `json:"name,omitempty" jsonschema:"Identity name (letters/digits/-/_, max 64; default 'default'). Errors if it already exists."`
}

type identityNewOutput struct {
	Name      string `json:"name"`
	Recipient string `json:"recipient"`
	Path      string `json:"path"`
}

// --- vault_identity_list ---

type identityListInput struct{}

type identityEntryOut struct {
	Name      string `json:"name"`
	Recipient string `json:"recipient"`
}

type identityListOutput struct {
	Identities []identityEntryOut `json:"identities"`
}

func (s *VaultMCPServer) registerIdentityTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_identity_new",
		Description: "Create a new X25519 identity keypair and store the private key 0600 under the vault's " +
			"identities directory. Returns ONLY the public recipient string (tvault1…) and the file path -- " +
			"the private key is NEVER returned. Use the recipient with vault_share_project or " +
			"vault_export_env_encrypted. Write op.",
	}, s.handleIdentityNew)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_identity_list",
		Description: "List local identities and their public recipient strings (tvault1…), so you can pick a " +
			"recipient to share or seal to. Public halves only; never returns private keys.",
	}, s.handleIdentityList)
}

func (s *VaultMCPServer) handleIdentityNew(_ context.Context, _ *sdkmcp.CallToolRequest, input identityNewInput) (*sdkmcp.CallToolResult, identityNewOutput, error) {
	if !s.policy.CanWrite() {
		return nil, identityNewOutput{}, fmt.Errorf("write access is disabled by policy")
	}
	name := input.Name
	if name == "" {
		name = "default"
	}
	recipient, path, err := identity.New(s.vault.Dir(), name)
	if err != nil {
		return nil, identityNewOutput{}, fmt.Errorf("create identity: %w", err)
	}
	s.audit("identity.create", "identity", name, map[string]any{"recipient": recipient})
	return nil, identityNewOutput{Name: name, Recipient: recipient, Path: path}, nil
}

func (s *VaultMCPServer) handleIdentityList(_ context.Context, _ *sdkmcp.CallToolRequest, _ identityListInput) (*sdkmcp.CallToolResult, identityListOutput, error) {
	entries, err := identity.List(s.vault.Dir())
	if err != nil {
		return nil, identityListOutput{}, fmt.Errorf("list identities: %w", err)
	}
	out := identityListOutput{Identities: make([]identityEntryOut, 0, len(entries))}
	for _, e := range entries {
		out.Identities = append(out.Identities, identityEntryOut{Name: e.Name, Recipient: e.Recipient})
	}
	return nil, out, nil
}
