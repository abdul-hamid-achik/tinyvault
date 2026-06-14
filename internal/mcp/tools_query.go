package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// --- vault_search_secrets ---

type searchSecretsInput struct {
	Project    string `json:"project,omitempty" jsonschema:"Project name to search within. If empty, search all projects."`
	Prefix     string `json:"prefix,omitempty" jsonschema:"Only return keys that start with this prefix."`
	NameLike   string `json:"name_like,omitempty" jsonschema:"SQL-style LIKE pattern with '*' as wildcard (e.g. 'STRIPE_*')."`
	Since      string `json:"since,omitempty" jsonschema:"Only return secrets updated at or after this RFC3339 timestamp."`
	Until      string `json:"until,omitempty" jsonschema:"Only return secrets updated at or before this RFC3339 timestamp."`
	MinVersion int    `json:"min_version,omitempty" jsonschema:"Only return secrets whose version is >= this value."`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum number of results. Default 1000."`
}

type secretRefOut struct {
	Project   string `json:"project"`
	Key       string `json:"key"`
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
}

type searchSecretsOutput struct {
	Results []secretRefOut `json:"results"`
	Count   int            `json:"count"`
}

// --- vault_list_secrets_by_prefix ---

type listByPrefixInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If empty, current project is used."`
	Prefix  string `json:"prefix" jsonschema:"Key prefix (e.g. 'STRIPE_')."`
	Limit   int    `json:"limit,omitempty" jsonschema:"Maximum number of results. Default 200."`
}

type listByPrefixOutput struct {
	Keys []string `json:"keys"`
}

// --- vault_audit_log_since ---

type auditLogSinceInput struct {
	Since    string `json:"since,omitempty" jsonschema:"Only return entries at or after this RFC3339 timestamp."`
	Until    string `json:"until,omitempty" jsonschema:"Only return entries at or before this RFC3339 timestamp."`
	Action   string `json:"action,omitempty" jsonschema:"Only entries with this action (e.g. 'secret.read')."`
	Resource string `json:"resource_type,omitempty" jsonschema:"Only entries with this resource type (e.g. 'secret')."`
	Limit    int    `json:"limit,omitempty" jsonschema:"Maximum entries. Default 100, max 1000."`
}

func (s *VaultMCPServer) registerQueryTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_search_secrets",
		Description: "Relational search across secrets: by project, key prefix, name pattern, " +
			"update time, or version. Returns metadata only (key name, project, version, " +
			"updated_at). Secret values are NEVER returned by this tool -- use " +
			"vault_run_with_secrets or vault_export_env when you need to use a value.",
	}, s.handleSearchSecrets)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_list_secrets_by_prefix",
		Description: "List secret keys that start with a given prefix. Cheaper than " +
			"vault_search_secrets when you know the prefix; preferred for autocomplete-style " +
			"and 'show me everything starting with STRIPE_' workflows.",
	}, s.handleListByPrefix)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_audit_log_since",
		Description: "Query the audit log with time-range and action filters. Returns " +
			"matching entries newest-first. Useful for 'what changed in the last hour?' " +
			"or 'when was this secret last touched?' workflows.",
	}, s.handleAuditLogSince)
}

func (s *VaultMCPServer) handleSearchSecrets(_ context.Context, _ *sdkmcp.CallToolRequest, input searchSecretsInput) (*sdkmcp.CallToolResult, searchSecretsOutput, error) {
	q := vault.SecretSearchQuery{
		Project:    input.Project,
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

	// If a project is specified, gate by policy.
	if q.Project != "" && !s.policy.CanAccessProject(q.Project) {
		return nil, searchSecretsOutput{}, fmt.Errorf("project %q is not allowed by policy", q.Project)
	}

	refs, err := s.vault.Search(q)
	if err != nil {
		return nil, searchSecretsOutput{}, fmt.Errorf("search: %w", err)
	}

	out := searchSecretsOutput{Results: []secretRefOut{}, Count: len(refs)}
	for _, r := range refs {
		if !s.policy.CanAccessProject(r.Project) {
			continue
		}
		if !s.policy.CanAccessSecret(r.Key) {
			continue
		}
		out.Results = append(out.Results, secretRefOut{
			Project:   r.Project,
			Key:       r.Key,
			Version:   r.Version,
			UpdatedAt: r.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	return nil, out, nil
}

func (s *VaultMCPServer) handleListByPrefix(_ context.Context, _ *sdkmcp.CallToolRequest, input listByPrefixInput) (*sdkmcp.CallToolResult, listByPrefixOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, listByPrefixOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 200
	}
	refs, err := s.vault.Search(vault.SecretSearchQuery{
		Project: project,
		Prefix:  input.Prefix,
		Limit:   limit,
	})
	if err != nil {
		return nil, listByPrefixOutput{}, fmt.Errorf("list by prefix: %w", err)
	}
	out := listByPrefixOutput{Keys: []string{}}
	for _, r := range refs {
		if !s.policy.CanAccessSecret(r.Key) {
			continue
		}
		out.Keys = append(out.Keys, r.Key)
	}
	return nil, out, nil
}

func (s *VaultMCPServer) handleAuditLogSince(_ context.Context, _ *sdkmcp.CallToolRequest, input auditLogSinceInput) (*sdkmcp.CallToolResult, auditLogOutput, error) {
	if !s.policy.CanWrite() && !strings.HasPrefix(s.policy.AccessMode, "read") {
		return nil, auditLogOutput{}, fmt.Errorf("audit log access is not allowed by policy")
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	filter := store.AuditFilter{
		Action:       input.Action,
		ResourceType: input.Resource,
		Limit:        limit,
	}
	if input.Since != "" {
		t, err := time.Parse(time.RFC3339, input.Since)
		if err != nil {
			return nil, auditLogOutput{}, fmt.Errorf("invalid since: %w", err)
		}
		filter.Since = t
	}
	if input.Until != "" {
		t, err := time.Parse(time.RFC3339, input.Until)
		if err != nil {
			return nil, auditLogOutput{}, fmt.Errorf("invalid until: %w", err)
		}
		filter.Until = t
	}
	entries, err := s.vault.ListAudit(filter)
	if err != nil {
		return nil, auditLogOutput{}, fmt.Errorf("list audit: %w", err)
	}
	if entries == nil {
		entries = []*store.AuditEntry{}
	}
	return nil, auditLogOutput{Entries: entries}, nil
}
