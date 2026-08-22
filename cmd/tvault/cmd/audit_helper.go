package cmd

import (
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// recordAudit writes a best-effort audit entry from the CLI for
// surface-specific actions (generate, share, env-group, identity reads).
// Primitive get/set/delete/create/rollback/history are recorded inside
// the vault layer so CLI, MCP, and the agent share one trail.
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
