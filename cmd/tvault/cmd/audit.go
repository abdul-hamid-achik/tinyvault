package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var (
	auditLimit        int
	auditSince        string
	auditUntil        string
	auditAction       string
	auditResourceType string
)

const auditMaxLimit = 1000

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "List recent vault audit-log entries",
	Long: `List recent audit-log entries (newest first).

The log is metadata only: actions, resource names, and timestamps. Secret
values are never stored in it and never printed by this command.

Audit is lock-free — it opens the vault without unlocking, so it works on
a locked vault and never prompts for a passphrase.

Examples:
  tvault audit
  tvault audit --limit 20
  tvault audit --action secret.read
  tvault audit --since 2026-01-01T00:00:00Z --json`,
	RunE: runAudit,
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().IntVar(&auditLimit, "limit", 100, "Maximum number of entries (default 100, max 1000)")
	auditCmd.Flags().StringVar(&auditSince, "since", "", "RFC3339 timestamp; only entries at or after")
	auditCmd.Flags().StringVar(&auditUntil, "until", "", "RFC3339 timestamp; only entries at or before")
	auditCmd.Flags().StringVar(&auditAction, "action", "", "Only entries with this action (e.g. secret.read)")
	auditCmd.Flags().StringVar(&auditResourceType, "resource-type", "", "Only entries with this resource type (e.g. secret)")
}

func runAudit(_ *cobra.Command, _ []string) error {
	if auditLimit < 1 || auditLimit > auditMaxLimit {
		return fmt.Errorf("--limit must be between 1 and %d", auditMaxLimit)
	}

	filter := store.AuditFilter{
		Action:       auditAction,
		ResourceType: auditResourceType,
		Limit:        auditLimit,
	}
	if auditSince != "" {
		t, err := time.Parse(time.RFC3339, auditSince)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		filter.Since = t
	}
	if auditUntil != "" {
		t, err := time.Parse(time.RFC3339, auditUntil)
		if err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
		filter.Until = t
	}

	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return wrapVaultOpenErr(dir, err)
	}
	defer v.Close()

	entries, err := v.ListAudit(filter)
	if err != nil {
		return fmt.Errorf("list audit: %w", err)
	}
	if entries == nil {
		entries = []*store.AuditEntry{}
	}

	if jsonOutput {
		return writeJSON(map[string]any{
			"count":   len(entries),
			"entries": entries,
		})
	}

	if len(entries) == 0 {
		fmt.Println("(no audit entries)")
		return nil
	}
	for _, e := range entries {
		name := e.ResourceName
		if name == "" {
			name = e.ResourceID
		}
		fmt.Printf("%s\t%s\t%s\t%s\n",
			e.Timestamp.UTC().Format(time.RFC3339),
			e.Action,
			e.ResourceType,
			name)
	}
	return nil
}
