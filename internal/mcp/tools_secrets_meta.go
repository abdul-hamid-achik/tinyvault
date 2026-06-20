package mcp

import (
	"context"
	"fmt"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// Richer secret-metadata listing tools. Both are metadata-only and NEVER
// return secret values.

// --- vault_list_secrets_detailed ---

type listSecretsDetailedInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If empty, the current project is used."`
}

type secretMetaOut struct {
	Key       string    `json:"key"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type listSecretsDetailedOutput struct {
	Project string          `json:"project"`
	Secrets []secretMetaOut `json:"secrets"`
}

// --- vault_list_secrets_global ---

type listSecretsGlobalInput struct {
	Prefix     string `json:"prefix,omitempty" jsonschema:"Only return keys that start with this prefix."`
	NameLike   string `json:"name_like,omitempty" jsonschema:"SQL-style LIKE pattern with '*' wildcard (e.g. 'STRIPE_*')."`
	Since      string `json:"since,omitempty" jsonschema:"Only return secrets updated at or after this RFC3339 timestamp."`
	Until      string `json:"until,omitempty" jsonschema:"Only return secrets updated at or before this RFC3339 timestamp."`
	MinVersion int    `json:"min_version,omitempty" jsonschema:"Only return secrets whose version is >= this value."`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum number of results. Default 1000."`
}

func (s *VaultMCPServer) registerSecretMetaTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_list_secrets_detailed",
		Description: "List secret keys in a project WITH per-key version and created/updated timestamps. " +
			"Metadata only; NEVER returns secret values. More accurate than vault_list_secrets (which " +
			"reports version 1 for every key).",
	}, s.handleListSecretsDetailed)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_list_secrets_global",
		Description: "Discover secrets across ALL accessible projects in one call, filtered by prefix, name " +
			"pattern, update time, or version. Returns metadata only (project, key, version, updated_at); " +
			"NEVER secret values.",
	}, s.handleListSecretsGlobal)
}

func (s *VaultMCPServer) handleListSecretsDetailed(_ context.Context, _ *sdkmcp.CallToolRequest, input listSecretsDetailedInput) (*sdkmcp.CallToolResult, listSecretsDetailedOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, listSecretsDetailedOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	metas, err := s.vault.ListSecretMetadata(project)
	if err != nil {
		return nil, listSecretsDetailedOutput{}, fmt.Errorf("list secrets: %w", err)
	}
	out := listSecretsDetailedOutput{Project: project, Secrets: []secretMetaOut{}}
	for _, m := range metas {
		if !s.policy.CanAccessSecret(m.Key) {
			continue
		}
		out.Secrets = append(out.Secrets, secretMetaOut{
			Key:       m.Key,
			Version:   m.Version,
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		})
	}
	return nil, out, nil
}

func (s *VaultMCPServer) handleListSecretsGlobal(_ context.Context, _ *sdkmcp.CallToolRequest, input listSecretsGlobalInput) (*sdkmcp.CallToolResult, searchSecretsOutput, error) {
	q := vault.SecretSearchQuery{
		Prefix:     input.Prefix,
		NameLike:   input.NameLike,
		MinVersion: input.MinVersion,
		Limit:      input.Limit,
	}
	if input.Since != "" {
		t, err := time.Parse(time.RFC3339, input.Since)
		if err != nil {
			return nil, searchSecretsOutput{}, fmt.Errorf("invalid since: %w", err)
		}
		q.Since = t
	}
	if input.Until != "" {
		t, err := time.Parse(time.RFC3339, input.Until)
		if err != nil {
			return nil, searchSecretsOutput{}, fmt.Errorf("invalid until: %w", err)
		}
		q.Until = t
	}
	refs, err := s.vault.Search(q)
	if err != nil {
		return nil, searchSecretsOutput{}, fmt.Errorf("search: %w", err)
	}
	out := searchSecretsOutput{Results: []secretRefOut{}}
	for _, r := range refs {
		if !s.policy.CanAccessProject(r.Project) || !s.policy.CanAccessSecret(r.Key) {
			continue
		}
		out.Results = append(out.Results, secretRefOut{
			Project:   r.Project,
			Key:       r.Key,
			Version:   r.Version,
			UpdatedAt: r.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	out.Count = len(out.Results)
	return nil, out, nil
}
