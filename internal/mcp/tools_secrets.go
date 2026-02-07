package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- vault_list_secrets ---

type listSecretsInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
}

type secretMeta struct {
	Key     string `json:"key"`
	Version int    `json:"version"`
}

type listSecretsOutput struct {
	Secrets []secretMeta `json:"secrets"`
}

// --- vault_get_secret ---

type getSecretInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Key     string `json:"key" jsonschema:"The secret key to retrieve."`
}

type getSecretOutput struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Warning string `json:"warning"`
}

// --- vault_set_secret ---

type setSecretInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Key     string `json:"key" jsonschema:"The secret key name."`
	Value   string `json:"value" jsonschema:"The secret value to store."`
}

type setSecretOutput struct {
	Key string `json:"key"`
}

// --- vault_delete_secret ---

type deleteSecretInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Key     string `json:"key" jsonschema:"The secret key to delete."`
}

type deleteSecretOutput struct {
	Key     string `json:"key"`
	Deleted bool   `json:"deleted"`
}

func (s *VaultMCPServer) registerSecretTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_list_secrets",
		Description: "List secret keys in a project. Returns only key names and metadata, NEVER secret values.",
	}, s.handleListSecrets)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_get_secret",
		Description: "Get the decrypted value of a specific secret. " +
			"WARNING: The secret value will be visible in the AI conversation context. " +
			"Use vault_run_with_secrets instead when you need to pass secrets to commands without exposing them.",
	}, s.handleGetSecret)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_set_secret",
		Description: "Create or update a secret in the vault. The value is encrypted at rest using AES-256-GCM.",
	}, s.handleSetSecret)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_delete_secret",
		Description: "Delete a secret from the vault. This action is irreversible.",
	}, s.handleDeleteSecret)
}

func (s *VaultMCPServer) handleListSecrets(_ context.Context, _ *sdkmcp.CallToolRequest, input listSecretsInput) (*sdkmcp.CallToolResult, listSecretsOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, listSecretsOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}

	keys, err := s.vault.ListSecrets(project)
	if err != nil {
		return nil, listSecretsOutput{}, fmt.Errorf("list secrets: %w", err)
	}

	var metas []secretMeta
	for _, k := range keys {
		if !s.policy.CanAccessSecret(k) {
			continue
		}
		metas = append(metas, secretMeta{Key: k, Version: 1})
	}

	if metas == nil {
		metas = []secretMeta{}
	}

	return nil, listSecretsOutput{Secrets: metas}, nil
}

func (s *VaultMCPServer) handleGetSecret(_ context.Context, _ *sdkmcp.CallToolRequest, input getSecretInput) (*sdkmcp.CallToolResult, getSecretOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, getSecretOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, getSecretOutput{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	value, err := s.vault.GetSecret(project, input.Key)
	if err != nil {
		return nil, getSecretOutput{}, fmt.Errorf("get secret: %w", err)
	}

	return nil, getSecretOutput{
		Key:     input.Key,
		Value:   value,
		Warning: "This value is now part of the AI conversation context.",
	}, nil
}

func (s *VaultMCPServer) handleSetSecret(_ context.Context, _ *sdkmcp.CallToolRequest, input setSecretInput) (*sdkmcp.CallToolResult, setSecretOutput, error) {
	if !s.policy.CanWrite() {
		return nil, setSecretOutput{}, fmt.Errorf("write operations are not allowed by policy (access_mode: %s)", s.policy.AccessMode)
	}

	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, setSecretOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, setSecretOutput{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	if err := s.vault.SetSecret(project, input.Key, input.Value); err != nil {
		return nil, setSecretOutput{}, fmt.Errorf("set secret: %w", err)
	}

	return nil, setSecretOutput{Key: input.Key}, nil
}

func (s *VaultMCPServer) handleDeleteSecret(_ context.Context, _ *sdkmcp.CallToolRequest, input deleteSecretInput) (*sdkmcp.CallToolResult, deleteSecretOutput, error) {
	if !s.policy.CanWrite() {
		return nil, deleteSecretOutput{}, fmt.Errorf("write operations are not allowed by policy (access_mode: %s)", s.policy.AccessMode)
	}

	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, deleteSecretOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, deleteSecretOutput{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	if err := s.vault.DeleteSecret(project, input.Key); err != nil {
		return nil, deleteSecretOutput{}, fmt.Errorf("delete secret: %w", err)
	}

	return nil, deleteSecretOutput{Key: input.Key, Deleted: true}, nil
}
