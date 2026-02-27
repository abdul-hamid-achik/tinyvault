package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type createProjectInput struct {
	Name        string `json:"name" jsonschema:"Project name to create."`
	Description string `json:"description,omitempty" jsonschema:"Optional project description."`
}

type createProjectOutput struct {
	Name    string `json:"name"`
	Created bool   `json:"created"`
}

type deleteProjectInput struct {
	Name string `json:"name" jsonschema:"Name of the project to delete."`
}

type deleteProjectOutput struct {
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

type listProjectsInput struct{}

type projectInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SecretCount int    `json:"secret_count"`
}

type listProjectsOutput struct {
	Projects []projectInfo `json:"projects"`
}

func (s *VaultMCPServer) registerProjectTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_list_projects",
		Description: "List all projects in the local TinyVault. Returns project names, descriptions, and secret counts.",
	}, s.handleListProjects)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_create_project",
		Description: "Create a new project in the vault with an isolated encryption key.",
	}, s.handleCreateProject)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_delete_project",
		Description: "Delete a project and all its secrets from the vault. This action is irreversible.",
	}, s.handleDeleteProject)
}

func (s *VaultMCPServer) handleListProjects(_ context.Context, _ *sdkmcp.CallToolRequest, _ listProjectsInput) (*sdkmcp.CallToolResult, listProjectsOutput, error) {
	projects, err := s.vault.ListProjects()
	if err != nil {
		return nil, listProjectsOutput{}, fmt.Errorf("list projects: %w", err)
	}

	var infos []projectInfo
	for _, p := range projects {
		if !s.policy.CanAccessProject(p.Name) {
			continue
		}
		keys, _ := s.vault.ListSecrets(p.Name) //nolint:errcheck // zero count is acceptable on error
		infos = append(infos, projectInfo{
			Name:        p.Name,
			Description: p.Description,
			SecretCount: len(keys),
		})
	}

	if infos == nil {
		infos = []projectInfo{}
	}

	return nil, listProjectsOutput{Projects: infos}, nil
}

func (s *VaultMCPServer) handleCreateProject(_ context.Context, _ *sdkmcp.CallToolRequest, input createProjectInput) (*sdkmcp.CallToolResult, createProjectOutput, error) {
	if !s.policy.CanWrite() {
		return nil, createProjectOutput{}, fmt.Errorf("write operations are not allowed by policy (access_mode: %s)", s.policy.AccessMode)
	}

	if _, err := s.vault.CreateProject(input.Name, input.Description); err != nil {
		return nil, createProjectOutput{}, fmt.Errorf("create project: %w", err)
	}

	s.audit("project.create", "project", input.Name, nil)

	return nil, createProjectOutput{Name: input.Name, Created: true}, nil
}

func (s *VaultMCPServer) handleDeleteProject(_ context.Context, _ *sdkmcp.CallToolRequest, input deleteProjectInput) (*sdkmcp.CallToolResult, deleteProjectOutput, error) {
	if !s.policy.CanWrite() {
		return nil, deleteProjectOutput{}, fmt.Errorf("write operations are not allowed by policy (access_mode: %s)", s.policy.AccessMode)
	}
	if !s.policy.CanAccessProject(input.Name) {
		return nil, deleteProjectOutput{}, fmt.Errorf("project %q is not allowed by policy", input.Name)
	}

	if err := s.vault.DeleteProject(input.Name); err != nil {
		return nil, deleteProjectOutput{}, fmt.Errorf("delete project: %w", err)
	}

	s.audit("project.delete", "project", input.Name, nil)

	return nil, deleteProjectOutput{Name: input.Name, Deleted: true}, nil
}
