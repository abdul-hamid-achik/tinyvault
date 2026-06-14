package cmd

import (
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// recordAudit writes a best-effort audit entry from the CLI. It uses the
// same action vocabulary as the MCP server (secret.read / secret.write /
// secret.delete / project.create / project.delete) so the audit log is
// uniform no matter which surface — CLI, TUI, or MCP — performed the
// action. Previously only the MCP server logged, so `tvault get/set/delete`
// were invisible in the audit log (and in the browser's Audit pane).
//
// Errors are intentionally ignored: audit is a safety net and must never
// block or fail a command. Writing audit does not require the vault to be
// unlocked (it only touches metadata).
func recordAudit(v *vault.Vault, action, resourceType, name string, metadata map[string]any) {
	if v == nil {
		return
	}
	//nolint:errcheck // audit is best-effort; errors must never block a command
	v.AppendAudit(&store.AuditEntry{
		Action:       action,
		ResourceType: resourceType,
		ResourceName: name,
		Timestamp:    time.Now().UTC(),
		Metadata:     metadata,
	})
}
