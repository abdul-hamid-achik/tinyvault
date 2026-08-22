package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

type generateSecretInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Key     string `json:"key" jsonschema:"The secret key name to store the generated value under."`
	Length  int    `json:"length,omitempty" jsonschema:"Length of the generated secret in characters (default 32)."`
	Charset string `json:"charset,omitempty" jsonschema:"Character set: alphanumeric, hex, base64, or ascii (default alphanumeric)."`
}

type generateSecretOutput struct {
	Key     string `json:"key"`
	Length  int    `json:"length"`
	Charset string `json:"charset"`
	Stored  bool   `json:"stored"`
}

func (s *VaultMCPServer) registerGenerateTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_generate_secret",
		Description: "Generate a cryptographically secure random secret and store it in the vault. " +
			"The generated value is NOT returned to the AI -- only the key, requested generation metadata, and storage confirmation.",
	}, s.handleGenerateSecret)
}

func (s *VaultMCPServer) handleGenerateSecret(_ context.Context, _ *sdkmcp.CallToolRequest, input generateSecretInput) (*sdkmcp.CallToolResult, generateSecretOutput, error) {
	if err := s.denyAgentWrite(); err != nil {
		return nil, generateSecretOutput{}, err
	}
	if !s.policy.CanWrite() {
		return nil, generateSecretOutput{}, fmt.Errorf("write operations are not allowed by policy (access_mode: %s)", s.policy.AccessMode)
	}

	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, generateSecretOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, generateSecretOutput{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	length := input.Length
	if length <= 0 {
		length = 32
	}

	charset := input.Charset
	if charset == "" {
		charset = "alphanumeric"
	}

	value, err := crypto.GenerateRandomString(length, charset)
	if err != nil {
		return nil, generateSecretOutput{}, fmt.Errorf("generate secret: %w", err)
	}

	if err := s.writeLockedHint(s.vault.SetSecret(project, input.Key, value)); err != nil {
		return nil, generateSecretOutput{}, fmt.Errorf("store secret: %w", err)
	}

	s.audit("secret.generate", "secret", input.Key, map[string]any{"project": project, "charset": charset, "length": length})

	return nil, generateSecretOutput{
		Key:     input.Key,
		Length:  length,
		Charset: charset,
		Stored:  true,
	}, nil
}
