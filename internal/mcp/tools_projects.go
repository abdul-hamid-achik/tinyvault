package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

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
		keys, _ := s.vault.ListSecrets(p.Name)
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
