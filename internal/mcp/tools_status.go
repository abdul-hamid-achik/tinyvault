package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// --- vault_status ---

type vaultStatusInput struct{}

type vaultStatusOutput = vault.Status

// --- vault_audit_log ---

type auditLogInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"Maximum number of entries to return (default 20, max 100)."`
}

type auditLogOutput struct {
	Entries []*store.AuditEntry `json:"entries"`
}

func (s *VaultMCPServer) registerStatusTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_status",
		Description: "Get vault status including lock state, project count, vault ID, and creation time.",
	}, s.handleVaultStatus)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_audit_log",
		Description: "Retrieve recent audit log entries showing actions performed on the vault.",
	}, s.handleAuditLog)
}

func (s *VaultMCPServer) handleVaultStatus(_ context.Context, _ *sdkmcp.CallToolRequest, _ vaultStatusInput) (*sdkmcp.CallToolResult, vaultStatusOutput, error) {
	return nil, s.vault.Status(), nil
}

func (s *VaultMCPServer) handleAuditLog(_ context.Context, _ *sdkmcp.CallToolRequest, input auditLogInput) (*sdkmcp.CallToolResult, auditLogOutput, error) {
	if !s.policy.CanWrite() && s.policy.AccessMode != "read-only" && s.policy.AccessMode != "read-write" && s.policy.AccessMode != "full" {
		return nil, auditLogOutput{}, fmt.Errorf("audit log access is not allowed by policy")
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	entries, err := s.vault.ListAudit(store.AuditFilter{Limit: limit})
	if err != nil {
		return nil, auditLogOutput{}, fmt.Errorf("list audit: %w", err)
	}

	if entries == nil {
		entries = []*store.AuditEntry{}
	}

	return nil, auditLogOutput{Entries: entries}, nil
}
