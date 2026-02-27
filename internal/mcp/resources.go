package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *VaultMCPServer) registerResources() {
	s.server.AddResource(&sdkmcp.Resource{
		URI:         "vault://status",
		Name:        "vault-status",
		Description: "Current vault status including lock state, project count, and metadata.",
		MIMEType:    "application/json",
	}, s.handleResourceStatus)

	s.server.AddResource(&sdkmcp.Resource{
		URI:         "vault://projects",
		Name:        "vault-projects",
		Description: "List of all accessible projects in the vault.",
		MIMEType:    "application/json",
	}, s.handleResourceProjects)

	s.server.AddResourceTemplate(&sdkmcp.ResourceTemplate{
		URITemplate: "vault://projects/{name}/keys",
		Name:        "project-keys",
		Description: "Secret key names for a specific project.",
		MIMEType:    "application/json",
	}, s.handleResourceProjectKeys)
}

func (s *VaultMCPServer) handleResourceStatus(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	status := s.vault.Status()
	data, err := json.Marshal(status)
	if err != nil {
		return nil, fmt.Errorf("marshal status: %w", err)
	}

	return &sdkmcp.ReadResourceResult{
		Contents: []*sdkmcp.ResourceContents{{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text:     string(data),
		}},
	}, nil
}

func (s *VaultMCPServer) handleResourceProjects(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	projects, err := s.vault.ListProjects()
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
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

	data, err := json.Marshal(infos)
	if err != nil {
		return nil, fmt.Errorf("marshal projects: %w", err)
	}

	return &sdkmcp.ReadResourceResult{
		Contents: []*sdkmcp.ResourceContents{{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text:     string(data),
		}},
	}, nil
}

func (s *VaultMCPServer) handleResourceProjectKeys(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	// Extract project name from URI: vault://projects/{name}/keys
	// The URI template matching gives us the full URI, we parse it.
	uri := req.Params.URI
	var name string
	_, err := fmt.Sscanf(uri, "vault://projects/%s", &name)
	if err != nil {
		return nil, fmt.Errorf("invalid resource URI: %s", uri)
	}
	// Remove trailing "/keys" if present
	if len(name) > 5 && name[len(name)-5:] == "/keys" {
		name = name[:len(name)-5]
	}

	if !s.policy.CanAccessProject(name) {
		return nil, fmt.Errorf("project %q is not allowed by policy", name)
	}

	keys, err := s.vault.ListSecrets(name)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	var filtered []string
	for _, k := range keys {
		if s.policy.CanAccessSecret(k) {
			filtered = append(filtered, k)
		}
	}
	if filtered == nil {
		filtered = []string{}
	}

	data, err := json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("marshal keys: %w", err)
	}

	return &sdkmcp.ReadResourceResult{
		Contents: []*sdkmcp.ResourceContents{{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text:     string(data),
		}},
	}, nil
}
