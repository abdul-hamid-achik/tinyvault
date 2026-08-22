package vault

import (
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
)

// recordOpAudit writes a best-effort audit row. A failed log must never fail
// the operation that produced it, and metadata must never include a secret
// value.
func (v *Vault) recordOpAudit(action, resourceType, name string, metadata map[string]any) {
	if v == nil {
		return
	}
	//nolint:errcheck // audit is best-effort
	_ = v.AppendAudit(makeAuditEntry(action, resourceType, name, metadata))
}

func makeAuditEntry(action, resourceType, name string, metadata map[string]any) *store.AuditEntry {
	return &store.AuditEntry{
		Action:       action,
		ResourceType: resourceType,
		ResourceName: name,
		Timestamp:    time.Now().UTC(),
		Metadata:     metadata,
	}
}

func mergeAuditMeta(base, extra map[string]any) map[string]any {
	if len(extra) == 0 {
		return base
	}
	out := make(map[string]any, len(base)+len(extra))
	for k, val := range base {
		out[k] = val
	}
	for k, val := range extra {
		out[k] = val
	}
	return out
}
