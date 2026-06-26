package studio

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
	path            string
	unlocked        bool
	currentProject  string
	projectCount    int
	vaultID         string
	createdAt       string
	envGroup        string // env group name if the current project is in one
	envName         string // environment name within the group
	envInheritsFrom string // base env if inheritance is configured
}

// envMembership is the per-project env-group info, used to annotate the
// projects pane and to cycle environments.
type envMembership struct {
	group string // group name
	env   string // environment name within the group
}

// loadStatus reads vault status + the current project name. It never
// requires the vault to be unlocked. If the current project is part of an
// environment group, the group name, environment name, and inheritance
// base are populated.
func loadStatus(v *vault.Vault) statusData {
	st := v.Status()
	cur, _ := v.GetCurrentProject() //nolint:errcheck // empty string is a fine default
	sd := statusData{
		path:           st.Path,
		unlocked:       st.IsUnlocked,
		currentProject: cur,
		projectCount:   st.ProjectCount,
		vaultID:        st.VaultID,
		createdAt:      st.CreatedAt,
	}
	// Look up env group membership for the current project.
	groups, _ := v.ListEnvGroups() //nolint:errcheck // best-effort; empty is fine
	for _, g := range groups {
		for _, e := range g.Environments {
			if e.Project == cur {
				sd.envGroup = g.Name
				sd.envName = e.Name
				if g.Inheritance != nil {
					if inh, ok := g.Inheritance[e.Name]; ok {
						sd.envInheritsFrom = inh.From
					}
				}
				return sd
			}
		}
	}
	return sd
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
// reveal/copy in the studio shows up in the Audit pane and the log.
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

// ---- env-group loaders ----

// loadEnvGroups returns all environment groups. Metadata only; never
// requires the vault to be unlocked.
func loadEnvGroups(v *vault.Vault) ([]vault.EnvGroup, error) {
	return v.ListEnvGroups()
}

// loadInherited returns the inherited-vs-local status of keys in a
// project that is part of an env group with inheritance configured.
// Metadata only; never decrypts.
func loadInherited(v *vault.Vault, groupName, envName string) ([]vault.InheritedKey, error) {
	return v.ListInherited(groupName, envName)
}

// loadDiff returns the key-set diff across environments in a group.
// It compares key sets only (no decryption), so it works when the vault
// is locked.
func loadDiff(v *vault.Vault, groupName string) (*vault.EnvDiff, error) {
	return v.DiffEnvironments(groupName, false)
}

// ---- env-group messages ----

type envGroupsLoadedMsg struct {
	groups []vault.EnvGroup
}

type inheritedLoadedMsg struct {
	group     string
	env       string
	inherited []vault.InheritedKey
}

type diffLoadedMsg struct {
	diff *vault.EnvDiff
}

type diffErrMsg struct {
	context string
	err     error
}

func (e diffErrMsg) Error() string { return e.context + ": " + e.err.Error() }

// ---- env-group command wrappers ----

func envGroupsCmd(v *vault.Vault) tea.Cmd {
	return func() tea.Msg {
		groups, err := loadEnvGroups(v)
		if err != nil {
			return errMsg{context: "load env groups", err: err}
		}
		return envGroupsLoadedMsg{groups: groups}
	}
}

func inheritedCmd(v *vault.Vault, groupName, envName string) tea.Cmd {
	return func() tea.Msg {
		inherited, err := loadInherited(v, groupName, envName)
		if err != nil {
			return errMsg{context: "load inherited", err: err}
		}
		return inheritedLoadedMsg{group: groupName, env: envName, inherited: inherited}
	}
}

func diffCmd(v *vault.Vault, groupName string) tea.Cmd {
	return func() tea.Msg {
		diff, err := loadDiff(v, groupName)
		if err != nil {
			return diffErrMsg{context: "env diff", err: err}
		}
		return diffLoadedMsg{diff: diff}
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

// revealInheritedCmd resolves a key through the env-group inheritance chain
// and reveals the value. The project field in the result is the child project
// (so the reveal map key matches the secrets pane entry).
func revealInheritedCmd(v *vault.Vault, groupName, envName, key, childProject string, epoch int) tea.Cmd {
	return func() tea.Msg {
		val, _, err := v.ResolveKey(groupName, envName, key)
		if err != nil {
			return errMsg{context: "reveal " + key, err: err}
		}
		// Audit the reveal of an inherited key.
		//nolint:errcheck // audit is best-effort
		v.AppendAudit(&store.AuditEntry{
			Action:       "secret.read",
			ResourceType: "secret",
			ResourceName: key,
			Timestamp:    time.Now().UTC(),
			Metadata:     map[string]any{"project": childProject, "source": "tui", "resolved_via": groupName + "/" + envName},
		})
		return revealedMsg{project: childProject, key: key, value: val, epoch: epoch}
	}
}
