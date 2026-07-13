package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

// X25519 recipient sharing tools. These manage who can open a project, never
// returning secret values or private keys.

// --- vault_share_project ---

type shareProjectInput struct {
	Recipient string `json:"recipient" jsonschema:"X25519 recipient string (tvault1…) to grant read access to the project."`
	Project   string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
}

type shareProjectOutput struct {
	Project   string `json:"project"`
	Recipient string `json:"recipient"`
	Shared    bool   `json:"shared"`
}

// --- vault_unshare_project ---

type unshareProjectInput struct {
	Recipient string `json:"recipient" jsonschema:"X25519 recipient string (tvault1…) to remove from the updated live vault."`
	Project   string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
}

type unshareProjectOutput struct {
	Project   string `json:"project"`
	Recipient string `json:"recipient"`
	Revoked   bool   `json:"revoked"`
}

// --- vault_project_recipients ---

type projectRecipientsInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
}

type projectRecipientsOutput struct {
	Project    string   `json:"project"`
	Recipients []string `json:"recipients"`
}

func (s *VaultMCPServer) registerSharingTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_share_project",
		Description: "Grant an X25519 recipient (tvault1…) read access to a project by wrapping its data key " +
			"to them -- no passphrase shared. The recipient can then read the project with their private " +
			"identity. Write op; returns metadata only.",
	}, s.handleShareProject)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_unshare_project",
		Description: "Remove a recipient from the updated live vault by rotating the project data key " +
			"and re-encrypting every current value and archived version. Pre-removal vault snapshots and " +
			"previously exported, sealed, or decrypted data remain readable; rotate underlying credentials " +
			"when needed. Write op; returns metadata only.",
	}, s.handleUnshareProject)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_project_recipients",
		Description: "List the X25519 recipients (public tvault1… strings) a project is currently shared with. " +
			"Metadata only; never returns private keys or secret values.",
	}, s.handleProjectRecipients)
}

// recipientOp validates write access, the recipient string, and the project,
// decodes the recipient, and runs op against the resolved project. It is the
// shared core of share/unshare so the two handlers stay thin.
func (s *VaultMCPServer) recipientOp(recipient, project string, op func(project string, pub []byte) error) (string, error) {
	if !s.policy.CanWrite() {
		return "", fmt.Errorf("write access is disabled by policy")
	}
	if recipient == "" {
		return "", fmt.Errorf("recipient is required")
	}
	pub, err := crypto.DecodeRecipient(recipient)
	if err != nil {
		return "", fmt.Errorf("recipient %q: %w", recipient, err)
	}
	proj := s.resolveProject(project)
	if !s.policy.CanAccessProject(proj) {
		return "", fmt.Errorf("project %q is not allowed by policy", proj)
	}
	if err := op(proj, pub); err != nil {
		return proj, err
	}
	return proj, nil
}

func (s *VaultMCPServer) handleShareProject(_ context.Context, _ *sdkmcp.CallToolRequest, input shareProjectInput) (*sdkmcp.CallToolResult, shareProjectOutput, error) {
	project, err := s.recipientOp(input.Recipient, input.Project, s.vault.ShareProject)
	if err != nil {
		return nil, shareProjectOutput{}, err
	}
	s.audit("project.share", "project", project, map[string]any{"project": project, "recipient": input.Recipient})
	return nil, shareProjectOutput{Project: project, Recipient: input.Recipient, Shared: true}, nil
}

func (s *VaultMCPServer) handleUnshareProject(_ context.Context, _ *sdkmcp.CallToolRequest, input unshareProjectInput) (*sdkmcp.CallToolResult, unshareProjectOutput, error) {
	project, err := s.recipientOp(input.Recipient, input.Project, s.vault.UnshareProject)
	if err != nil {
		return nil, unshareProjectOutput{}, err
	}
	s.audit("project.unshare", "project", project, map[string]any{"project": project, "recipient": input.Recipient})
	return nil, unshareProjectOutput{Project: project, Recipient: input.Recipient, Revoked: true}, nil
}

func (s *VaultMCPServer) handleProjectRecipients(_ context.Context, _ *sdkmcp.CallToolRequest, input projectRecipientsInput) (*sdkmcp.CallToolResult, projectRecipientsOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, projectRecipientsOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	pubs, err := s.vault.ProjectRecipients(project)
	if err != nil {
		return nil, projectRecipientsOutput{}, fmt.Errorf("recipients: %w", err)
	}
	out := projectRecipientsOutput{Project: project, Recipients: []string{}}
	for _, pub := range pubs {
		out.Recipients = append(out.Recipients, crypto.EncodeRecipient(pub))
	}
	return nil, out, nil
}
