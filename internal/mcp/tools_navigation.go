package mcp

import (
	"context"
	"fmt"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Navigation / project-discovery tools. All metadata-only; no secret values.

// --- vault_get_current_project ---

type getCurrentProjectInput struct{}

type getCurrentProjectOutput struct {
	CurrentProject string `json:"current_project"`
}

// --- vault_set_current_project ---

type setCurrentProjectInput struct {
	Name string `json:"name" jsonschema:"The project to make the current/default project."`
}

type setCurrentProjectOutput struct {
	Name string `json:"name"`
	Set  bool   `json:"set"`
}

// --- vault_count_secrets ---

type countSecretsInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If empty, the current project is used."`
}

type countSecretsOutput struct {
	Project string `json:"project"`
	Count   int    `json:"count"`
}

// --- vault_search_projects ---

type searchProjectsInput struct {
	NameLike        string `json:"name_like,omitempty" jsonschema:"SQL-style LIKE pattern over project names with '*' wildcard (e.g. 'web-*')."`
	DescriptionLike string `json:"description_like,omitempty" jsonschema:"SQL-style LIKE pattern over project descriptions with '*' wildcard."`
	Limit           int    `json:"limit,omitempty" jsonschema:"Maximum number of results."`
}

type searchProjectsOutput struct {
	Projects []string `json:"projects"`
}

// --- vault_projects_overview ---

type projectsOverviewInput struct{}

type projectOverviewItem struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	SecretCount int       `json:"secret_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type projectsOverviewOutput struct {
	Projects []projectOverviewItem `json:"projects"`
}

func (s *VaultMCPServer) registerNavigationTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_get_current_project",
		Description: "Report the vault's current/default project -- what a tool resolves to when its " +
			"'project' argument is omitted. Orient with this before other calls.",
	}, s.handleGetCurrentProject)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_set_current_project",
		Description: "Switch the vault's current/default project so subsequent project-less calls target it. " +
			"Write op.",
	}, s.handleSetCurrentProject)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_count_secrets",
		Description: "Count the secrets in a project without listing keys or values. Cheap; metadata only.",
	}, s.handleCountSecrets)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_search_projects",
		Description: "Find projects by name or description glob ('*' wildcard). Complements vault_list_projects " +
			"for large vaults. Returns project names only.",
	}, s.handleSearchProjects)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_projects_overview",
		Description: "List every accessible project with its description, secret count, and created/updated " +
			"timestamps in one call. Metadata only; no secret values.",
	}, s.handleProjectsOverview)
}

func (s *VaultMCPServer) handleGetCurrentProject(_ context.Context, _ *sdkmcp.CallToolRequest, _ getCurrentProjectInput) (*sdkmcp.CallToolResult, getCurrentProjectOutput, error) {
	name, err := s.vault.GetCurrentProject()
	if err != nil {
		return nil, getCurrentProjectOutput{}, fmt.Errorf("get current project: %w", err)
	}
	if name == "" {
		name = "default"
	}
	return nil, getCurrentProjectOutput{CurrentProject: name}, nil
}

func (s *VaultMCPServer) handleSetCurrentProject(_ context.Context, _ *sdkmcp.CallToolRequest, input setCurrentProjectInput) (*sdkmcp.CallToolResult, setCurrentProjectOutput, error) {
	if !s.policy.CanWrite() {
		return nil, setCurrentProjectOutput{}, fmt.Errorf("write access is disabled by policy")
	}
	if input.Name == "" {
		return nil, setCurrentProjectOutput{}, fmt.Errorf("name is required")
	}
	if !s.policy.CanAccessProject(input.Name) {
		return nil, setCurrentProjectOutput{}, fmt.Errorf("project %q is not allowed by policy", input.Name)
	}
	if err := s.vault.SetCurrentProject(input.Name); err != nil {
		return nil, setCurrentProjectOutput{}, fmt.Errorf("set current project: %w", err)
	}
	s.audit("project.use", "project", input.Name, map[string]any{"project": input.Name})
	return nil, setCurrentProjectOutput{Name: input.Name, Set: true}, nil
}

func (s *VaultMCPServer) handleCountSecrets(_ context.Context, _ *sdkmcp.CallToolRequest, input countSecretsInput) (*sdkmcp.CallToolResult, countSecretsOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, countSecretsOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	count, err := s.vault.CountSecrets(project)
	if err != nil {
		return nil, countSecretsOutput{}, fmt.Errorf("count secrets: %w", err)
	}
	return nil, countSecretsOutput{Project: project, Count: count}, nil
}

func (s *VaultMCPServer) handleSearchProjects(_ context.Context, _ *sdkmcp.CallToolRequest, input searchProjectsInput) (*sdkmcp.CallToolResult, searchProjectsOutput, error) {
	names, err := s.vault.SearchProjects(input.NameLike, input.DescriptionLike, input.Limit)
	if err != nil {
		return nil, searchProjectsOutput{}, fmt.Errorf("search projects: %w", err)
	}
	out := searchProjectsOutput{Projects: []string{}}
	for _, n := range names {
		if s.policy.CanAccessProject(n) {
			out.Projects = append(out.Projects, n)
		}
	}
	return nil, out, nil
}

func (s *VaultMCPServer) handleProjectsOverview(_ context.Context, _ *sdkmcp.CallToolRequest, _ projectsOverviewInput) (*sdkmcp.CallToolResult, projectsOverviewOutput, error) {
	snaps, err := s.vault.SnapshotProjects()
	if err != nil {
		return nil, projectsOverviewOutput{}, fmt.Errorf("projects overview: %w", err)
	}
	out := projectsOverviewOutput{Projects: []projectOverviewItem{}}
	for _, p := range snaps {
		if !s.policy.CanAccessProject(p.Name) {
			continue
		}
		out.Projects = append(out.Projects, projectOverviewItem{
			Name:        p.Name,
			Description: p.Description,
			SecretCount: p.SecretCount,
			CreatedAt:   p.CreatedAt,
			UpdatedAt:   p.UpdatedAt,
		})
	}
	return nil, out, nil
}
