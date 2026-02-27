package mcp

import (
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
)

// audit logs an action to the vault's audit log. Errors are silently ignored
// because audit is best-effort and should never block operations.
func (s *VaultMCPServer) audit(action, resourceType, resourceName string, metadata map[string]any) {
	_ = s.vault.AppendAudit(&store.AuditEntry{
		Action:       action,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Timestamp:    time.Now().UTC(),
		Metadata:     metadata,
	})
}
