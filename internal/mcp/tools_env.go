package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type exportEnvInput struct {
	Project    string   `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Format     string   `json:"format,omitempty" jsonschema:"Output format: dotenv json or shell. Default: dotenv."`
	OutputPath string   `json:"output_path,omitempty" jsonschema:"File path to write to. Default: .env"`
	Keys       []string `json:"keys,omitempty" jsonschema:"Specific secret keys to export. If omitted exports all."`
}

type exportEnvOutput struct {
	Path  string   `json:"path"`
	Count int      `json:"count"`
	Keys  []string `json:"keys"`
}

func (s *VaultMCPServer) registerEnvTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_export_env",
		Description: "Write project secrets to a .env file, JSON file, or shell export statements. " +
			"The file is written directly to disk -- secret values are NOT returned to the AI conversation. " +
			"Only the file path and key names are returned.",
	}, s.handleExportEnv)
}

//nolint:gocognit // sequential format handling is clearest as a single function
func (s *VaultMCPServer) handleExportEnv(_ context.Context, _ *sdkmcp.CallToolRequest, input exportEnvInput) (*sdkmcp.CallToolResult, exportEnvOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, exportEnvOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}

	allSecrets, err := s.vault.GetAllSecrets(project)
	if err != nil {
		return nil, exportEnvOutput{}, fmt.Errorf("get secrets: %w", err)
	}

	// Filter to requested keys if specified.
	secrets := allSecrets
	if len(input.Keys) > 0 {
		secrets = make(map[string]string, len(input.Keys))
		for _, key := range input.Keys {
			val, ok := allSecrets[key]
			if !ok {
				return nil, exportEnvOutput{}, fmt.Errorf("secret %q not found in project %q", key, project)
			}
			secrets[key] = val
		}
	}

	// Filter by policy.
	filtered := make(map[string]string, len(secrets))
	for k, v := range secrets {
		if s.policy.CanAccessSecret(k) {
			filtered[k] = v
		}
	}

	format := input.Format
	if format == "" {
		format = "dotenv"
	}

	outputPath := input.OutputPath
	if outputPath == "" {
		switch format {
		case "json":
			outputPath = ".env.json"
		default:
			outputPath = ".env"
		}
	}

	var content string
	switch format {
	case "dotenv":
		var b strings.Builder
		for k, v := range filtered {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
		content = b.String()
	case "shell":
		var b strings.Builder
		for k, v := range filtered {
			fmt.Fprintf(&b, "export %s=%q\n", k, v)
		}
		content = b.String()
	case "json":
		data, err := json.MarshalIndent(filtered, "", "  ")
		if err != nil {
			return nil, exportEnvOutput{}, fmt.Errorf("marshal json: %w", err)
		}
		content = string(data) + "\n"
	default:
		return nil, exportEnvOutput{}, fmt.Errorf("unsupported format: %s (use dotenv, json, or shell)", format)
	}

	if err := os.WriteFile(outputPath, []byte(content), 0o600); err != nil {
		return nil, exportEnvOutput{}, fmt.Errorf("write file: %w", err)
	}

	keys := make([]string, 0, len(filtered))
	for k := range filtered {
		keys = append(keys, k)
	}

	return nil, exportEnvOutput{
		Path:  outputPath,
		Count: len(filtered),
		Keys:  keys,
	}, nil
}
