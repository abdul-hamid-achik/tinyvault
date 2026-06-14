package mcp

import (
	"context"
	"fmt"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Version history + rollback tools. Both are value-free by construction: the
// output structs carry no plaintext/ciphertext field, and the handlers never
// call GetSecretVersionValue. History is metadata-only (read-equivalent);
// rollback is a write op gated by CanWrite and returns only version numbers.

// --- vault_secret_history ---

type secretHistoryInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Key     string `json:"key" jsonschema:"The secret key whose version history to list."`
}

type secretVersionMeta struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type secretHistoryOutput struct {
	Versions []secretVersionMeta `json:"versions"`
}

// --- vault_rollback_secret ---

type rollbackSecretInput struct {
	Project   string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Key       string `json:"key" jsonschema:"The secret key to roll back."`
	ToVersion int    `json:"to_version" jsonschema:"The version number to restore as a new current version."`
}

type rollbackSecretOutput struct {
	RolledBack     bool `json:"rolled_back"`
	RolledBackFrom int  `json:"rolled_back_from"`
	NewVersion     int  `json:"new_version"`
}

func (s *VaultMCPServer) registerVersionTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_secret_history",
		Description: "List the version history (metadata only) of a secret: version numbers and " +
			"created/updated timestamps. NEVER returns secret values.",
	}, s.handleSecretHistory)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_rollback_secret",
		Description: "Restore an earlier version of a secret as a new current version. Non-destructive " +
			"(the prior value is archived; version numbers are never reused). Returns only version numbers, " +
			"never a secret value.",
	}, s.handleRollbackSecret)
}

func (s *VaultMCPServer) handleSecretHistory(_ context.Context, _ *sdkmcp.CallToolRequest, input secretHistoryInput) (*sdkmcp.CallToolResult, secretHistoryOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, secretHistoryOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, secretHistoryOutput{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	versions, err := s.vault.ListSecretVersions(project, input.Key)
	if err != nil {
		return nil, secretHistoryOutput{}, fmt.Errorf("history: %w", err)
	}
	out := secretHistoryOutput{Versions: make([]secretVersionMeta, 0, len(versions))}
	for _, v := range versions {
		out.Versions = append(out.Versions, secretVersionMeta{
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
			UpdatedAt: v.UpdatedAt,
		})
	}
	s.audit("secret.read", "secret", input.Key, map[string]any{"project": project, "source": "history"})
	return nil, out, nil
}

func (s *VaultMCPServer) handleRollbackSecret(_ context.Context, _ *sdkmcp.CallToolRequest, input rollbackSecretInput) (*sdkmcp.CallToolResult, rollbackSecretOutput, error) {
	if !s.policy.CanWrite() {
		return nil, rollbackSecretOutput{}, fmt.Errorf("write access is disabled by policy")
	}
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, rollbackSecretOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, rollbackSecretOutput{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	newVersion, err := s.vault.RollbackSecret(project, input.Key, input.ToVersion)
	if err != nil {
		return nil, rollbackSecretOutput{}, fmt.Errorf("rollback: %w", err)
	}
	s.audit("secret.rollback", "secret", input.Key, map[string]any{
		"project":      project,
		"from_version": input.ToVersion,
		"new_version":  newVersion,
	})
	return nil, rollbackSecretOutput{RolledBack: true, RolledBackFrom: input.ToVersion, NewVersion: newVersion}, nil
}
