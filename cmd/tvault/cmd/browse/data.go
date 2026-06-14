package browse

import (
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// This file is the only bridge between the TUI and internal/vault. It
// wraps existing read-only vault methods; it adds NO new logic to the
// vault. Every loader has a plain function form (tested directly against
// a scratch vault) and a tea.Cmd form (used by the model's Update loop).

// statusData is the header/status-pane snapshot. Aggregate counts
// (total secrets, last write) are derived in the model from the loaded
// project snapshots, keeping a single source of truth.
type statusData struct {
	path           string
	unlocked       bool
	currentProject string
	projectCount   int
	vaultID        string
	createdAt      string
}

// loadStatus reads vault status + the current project name. It never
// requires the vault to be unlocked.
func loadStatus(v *vault.Vault) statusData {
	st := v.Status()
	cur, _ := v.GetCurrentProject() //nolint:errcheck // empty string is a fine default
	return statusData{
		path:           st.Path,
		unlocked:       st.IsUnlocked,
		currentProject: cur,
		projectCount:   st.ProjectCount,
		vaultID:        st.VaultID,
		createdAt:      st.CreatedAt,
	}
}

// loadProjects returns one snapshot per project (name + secret count +
// timestamps). Metadata only; never decrypts.
func loadProjects(v *vault.Vault) ([]vault.ProjectSnapshot, error) {
	return v.SnapshotProjects()
}

// loadSecrets returns the secret refs (key + version + mtime, no value)
// for a single project, in (project, key) order.
func loadSecrets(v *vault.Vault, project string) ([]vault.SecretRef, error) {
	if project == "" {
		return nil, nil
	}
	return v.Search(vault.SecretSearchQuery{Project: project})
}

// loadAudit returns the most recent audit entries (newest first).
func loadAudit(v *vault.Vault, limit int) ([]*store.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	return v.ListAudit(store.AuditFilter{Limit: limit})
}

// revealSecret decrypts a single value. Requires the vault to be
// unlocked; returns vault.ErrLocked otherwise. A successful decrypt is
// audited as a secret.read (same vocabulary as the CLI and MCP), so a
// reveal/copy in the browser shows up in the Audit pane and the log.
func revealSecret(v *vault.Vault, project, key string) (string, error) {
	val, err := v.GetSecret(project, key)
	if err == nil {
		//nolint:errcheck // audit is best-effort; never block a reveal
		v.AppendAudit(&store.AuditEntry{
			Action:       "secret.read",
			ResourceType: "secret",
			ResourceName: key,
			Timestamp:    time.Now().UTC(),
			Metadata:     map[string]any{"project": project, "source": "tui"},
		})
	}
	return val, err
}

// ---- messages ----

type statusLoadedMsg statusData

type projectsLoadedMsg struct {
	projects []vault.ProjectSnapshot
}

type secretsLoadedMsg struct {
	project string
	refs    []vault.SecretRef
}

type auditLoadedMsg struct {
	entries []*store.AuditEntry
}

type revealedMsg struct {
	project string
	key     string
	value   string
	epoch   int // reveal generation; stale (pre-wipe) reveals are dropped
}

type errMsg struct {
	context string
	err     error
}

// ---- command wrappers ----

func statusCmd(v *vault.Vault) tea.Cmd {
	return func() tea.Msg { return statusLoadedMsg(loadStatus(v)) }
}

func projectsCmd(v *vault.Vault) tea.Cmd {
	return func() tea.Msg {
		projects, err := loadProjects(v)
		if err != nil {
			return errMsg{context: "load projects", err: err}
		}
		return projectsLoadedMsg{projects: projects}
	}
}

func secretsCmd(v *vault.Vault, project string) tea.Cmd {
	return func() tea.Msg {
		refs, err := loadSecrets(v, project)
		if err != nil {
			return errMsg{context: "load secrets", err: err}
		}
		return secretsLoadedMsg{project: project, refs: refs}
	}
}

func auditCmd(v *vault.Vault, limit int) tea.Cmd {
	return func() tea.Msg {
		entries, err := loadAudit(v, limit)
		if err != nil {
			return errMsg{context: "load audit", err: err}
		}
		return auditLoadedMsg{entries: entries}
	}
}

// mutationDoneMsg signals a successful in-app write/delete (--rw mode), so
// the model can re-mask, reload, and confirm.
type mutationDoneMsg struct {
	action string // "set" | "delete"
	key    string
}

// auditTUI writes a best-effort audit entry for a TUI action (source:tui),
// matching the CLI/MCP vocabulary.
func auditTUI(v *vault.Vault, action, key, project string) {
	//nolint:errcheck // audit is best-effort; never block a mutation
	v.AppendAudit(&store.AuditEntry{
		Action:       action,
		ResourceType: "secret",
		ResourceName: key,
		Timestamp:    time.Now().UTC(),
		Metadata:     map[string]any{"project": project, "source": "tui"},
	})
}

func setSecretCmd(v *vault.Vault, project, key, value string) tea.Cmd {
	return func() tea.Msg {
		if err := v.SetSecret(project, key, value); err != nil {
			return errMsg{context: "set " + key, err: err}
		}
		auditTUI(v, "secret.write", key, project)
		return mutationDoneMsg{action: "set", key: key}
	}
}

func deleteSecretCmd(v *vault.Vault, project, key string) tea.Cmd {
	return func() tea.Msg {
		if err := v.DeleteSecret(project, key); err != nil {
			return errMsg{context: "delete " + key, err: err}
		}
		auditTUI(v, "secret.delete", key, project)
		return mutationDoneMsg{action: "delete", key: key}
	}
}

func revealCmd(v *vault.Vault, project, key string, epoch int) tea.Cmd {
	return func() tea.Msg {
		val, err := revealSecret(v, project, key)
		if err != nil {
			return errMsg{context: "reveal " + key, err: err}
		}
		return revealedMsg{project: project, key: key, value: val, epoch: epoch}
	}
}
