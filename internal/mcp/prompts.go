package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *VaultMCPServer) registerPrompts() {
	s.server.AddPrompt(&sdkmcp.Prompt{
		Name:        "setup-project",
		Description: "Step-by-step guide to create and configure a new vault project with initial secrets.",
		Arguments: []*sdkmcp.PromptArgument{
			{Name: "name", Description: "Name for the new project", Required: true},
		},
	}, s.handleSetupProjectPrompt)

	s.server.AddPrompt(&sdkmcp.Prompt{
		Name:        "inject-secrets",
		Description: "Guide to run a command with vault secrets injected as environment variables.",
		Arguments: []*sdkmcp.PromptArgument{
			{Name: "project", Description: "Project name (optional, uses current project if omitted)", Required: false},
			{Name: "command", Description: "The command to run with secrets", Required: true},
		},
	}, s.handleInjectSecretsPrompt)
}

func (s *VaultMCPServer) handleSetupProjectPrompt(_ context.Context, req *sdkmcp.GetPromptRequest) (*sdkmcp.GetPromptResult, error) {
	name := req.Params.Arguments["name"]
	if name == "" {
		return nil, fmt.Errorf("project name is required")
	}

	return &sdkmcp.GetPromptResult{
		Description: fmt.Sprintf("Set up a new vault project: %s", name),
		Messages: []*sdkmcp.PromptMessage{
			{
				Role: "user",
				Content: &sdkmcp.TextContent{
					Text: fmt.Sprintf(`Help me set up a new TinyVault project called %q. Follow these steps:

1. Create the project using vault_create_project with the name %q
2. Ask me what secrets I need to add to this project
3. For each secret I mention, use vault_set_secret to store it in the %q project
4. After adding all secrets, use vault_list_secrets to verify the project is configured correctly
5. Summarize what was created`, name, name, name),
				},
			},
		},
	}, nil
}

func (s *VaultMCPServer) handleInjectSecretsPrompt(_ context.Context, req *sdkmcp.GetPromptRequest) (*sdkmcp.GetPromptResult, error) {
	command := req.Params.Arguments["command"]
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}

	project := req.Params.Arguments["project"]
	projectClause := "the current project"
	if project != "" {
		projectClause = fmt.Sprintf("the %q project", project)
	}

	return &sdkmcp.GetPromptResult{
		Description: fmt.Sprintf("Run command with secrets from %s", projectClause),
		Messages: []*sdkmcp.PromptMessage{
			{
				Role: "user",
				Content: &sdkmcp.TextContent{
					Text: fmt.Sprintf(`Help me run a command with secrets injected from %s. Follow these steps:

1. First, use vault_list_secrets to check what secrets are available in %s
2. Run the command %q using vault_run_with_secrets, injecting the project secrets
3. Check the output and report any issues (note: secret values will be redacted in the output)`, projectClause, projectClause, command),
				},
			},
		},
	}, nil
}
