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
func loadStatus(s *Session) (statusData, error) {
	var sd statusData
	err := s.with(func(v *vault.Vault) error {
		st := v.Status()
		cur, _ := v.GetCurrentProject() //nolint:errcheck // empty string is a fine default
		sd = statusData{
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
				if e.Project != cur {
					continue
				}
				sd.envGroup = g.Name
				sd.envName = e.Name
				if g.Inheritance != nil {
					if inh, ok := g.Inheritance[e.Name]; ok {
						sd.envInheritsFrom = inh.From
					}
				}
				return nil
			}
		}
		return nil
	})
	return sd, err
}

// loadProjects returns one snapshot per project (name + secret count +
// timestamps). Metadata only; never decrypts.
func loadProjects(s *Session) ([]vault.ProjectSnapshot, error) {
	var out []vault.ProjectSnapshot
	err := s.with(func(v *vault.Vault) error {
		var e error
		out, e = v.SnapshotProjects()
		return e
	})
	return out, err
}

// loadSecrets returns the secret refs (key + version + mtime, no value)
// for a single project, in (project, key) order.
func loadSecrets(s *Session, project string) ([]vault.SecretRef, error) {
	if project == "" {
		return nil, nil
	}
	var out []vault.SecretRef
	err := s.with(func(v *vault.Vault) error {
		var e error
		out, e = v.Search(vault.SecretSearchQuery{Project: project})
		return e
	})
	return out, err
}

// loadAudit returns the most recent audit entries (newest first).
func loadAudit(s *Session, limit int) ([]*store.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []*store.AuditEntry
	err := s.with(func(v *vault.Vault) error {
		var e error
		out, e = v.ListAudit(store.AuditFilter{Limit: limit})
		return e
	})
	return out, err
}

// revealSecret decrypts a single value. Requires the vault to be
// unlocked; returns vault.ErrLocked otherwise. A successful decrypt is
// audited as a secret.read (same vocabulary as the CLI and MCP), so a
// reveal/copy in the studio shows up in the Audit pane and the log.
func revealSecret(s *Session, project, key string) (string, error) {
	var val string
	err := s.with(func(v *vault.Vault) error {
		var e error
		val, e = v.GetSecret(project, key)
		if e != nil {
			return e
		}
		//nolint:errcheck // audit is best-effort; never block a reveal
		v.AppendAudit(&store.AuditEntry{
			Action:       "secret.read",
			ResourceType: "secret",
			ResourceName: key,
			Timestamp:    time.Now().UTC(),
			Metadata:     map[string]any{"project": project, "source": "tui"},
		})
		return nil
	})
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

func statusCmd(s *Session) tea.Cmd {
	return func() tea.Msg {
		sd, err := loadStatus(s)
		if err != nil {
			return errMsg{context: "load status", err: err}
		}
		return statusLoadedMsg(sd)
	}
}

func projectsCmd(s *Session) tea.Cmd {
	return func() tea.Msg {
		projects, err := loadProjects(s)
		if err != nil {
			return errMsg{context: "load projects", err: err}
		}
		return projectsLoadedMsg{projects: projects}
	}
}

func secretsCmd(s *Session, project string) tea.Cmd {
	return func() tea.Msg {
		refs, err := loadSecrets(s, project)
		if err != nil {
			return errMsg{context: "load secrets", err: err}
		}
		return secretsLoadedMsg{project: project, refs: refs}
	}
}

func auditCmd(s *Session, limit int) tea.Cmd {
	return func() tea.Msg {
		entries, err := loadAudit(s, limit)
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

func setSecretCmd(s *Session, project, key, value string) tea.Cmd {
	return func() tea.Msg {
		err := s.with(func(v *vault.Vault) error {
			if e := v.SetSecret(project, key, value); e != nil {
				return e
			}
			auditTUI(v, "secret.write", key, project)
			return nil
		})
		if err != nil {
			return errMsg{context: "set " + key, err: err}
		}
		return mutationDoneMsg{action: "set", key: key}
	}
}

func deleteSecretCmd(s *Session, project, key string) tea.Cmd {
	return func() tea.Msg {
		err := s.with(func(v *vault.Vault) error {
			if e := v.DeleteSecret(project, key); e != nil {
				return e
			}
			auditTUI(v, "secret.delete", key, project)
			return nil
		})
		if err != nil {
			return errMsg{context: "delete " + key, err: err}
		}
		return mutationDoneMsg{action: "delete", key: key}
	}
}

// ---- env-group loaders ----

// loadEnvGroups returns all environment groups. Metadata only; never
// requires the vault to be unlocked.
func loadEnvGroups(s *Session) ([]vault.EnvGroup, error) {
	var out []vault.EnvGroup
	err := s.with(func(v *vault.Vault) error {
		var e error
		out, e = v.ListEnvGroups()
		return e
	})
	return out, err
}

// loadInherited returns the inherited-vs-local status of keys in a
// project that is part of an env group with inheritance configured.
// Metadata only; never decrypts.
func loadInherited(s *Session, groupName, envName string) ([]vault.InheritedKey, error) {
	var out []vault.InheritedKey
	err := s.with(func(v *vault.Vault) error {
		var e error
		out, e = v.ListInherited(groupName, envName)
		return e
	})
	return out, err
}

// loadDiff returns the key-set diff across environments in a group.
// It compares key sets only (no decryption), so it works when the vault
// is locked.
func loadDiff(s *Session, groupName string) (*vault.EnvDiff, error) {
	var out *vault.EnvDiff
	err := s.with(func(v *vault.Vault) error {
		var e error
		out, e = v.DiffEnvironments(groupName, false)
		return e
	})
	return out, err
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

func envGroupsCmd(s *Session) tea.Cmd {
	return func() tea.Msg {
		groups, err := loadEnvGroups(s)
		if err != nil {
			return errMsg{context: "load env groups", err: err}
		}
		return envGroupsLoadedMsg{groups: groups}
	}
}

func inheritedCmd(s *Session, groupName, envName string) tea.Cmd {
	return func() tea.Msg {
		inherited, err := loadInherited(s, groupName, envName)
		if err != nil {
			return errMsg{context: "load inherited", err: err}
		}
		return inheritedLoadedMsg{group: groupName, env: envName, inherited: inherited}
	}
}

func diffCmd(s *Session, groupName string) tea.Cmd {
	return func() tea.Msg {
		diff, err := loadDiff(s, groupName)
		if err != nil {
			return diffErrMsg{context: "env diff", err: err}
		}
		return diffLoadedMsg{diff: diff}
	}
}

func revealCmd(s *Session, project, key string, epoch int) tea.Cmd {
	return func() tea.Msg {
		val, err := revealSecret(s, project, key)
		if err != nil {
			return errMsg{context: "reveal " + key, err: err}
		}
		return revealedMsg{project: project, key: key, value: val, epoch: epoch}
	}
}

// revealInheritedCmd resolves a key through the env-group inheritance chain
// and reveals the value. The project field in the result is the child project
// (so the reveal map key matches the secrets pane entry).
func revealInheritedCmd(s *Session, groupName, envName, key, childProject string, epoch int) tea.Cmd {
	return func() tea.Msg {
		var val string
		err := s.with(func(v *vault.Vault) error {
			var e error
			val, _, e = v.ResolveKey(groupName, envName, key)
			if e != nil {
				return e
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
			return nil
		})
		if err != nil {
			return errMsg{context: "reveal " + key, err: err}
		}
		return revealedMsg{project: childProject, key: key, value: val, epoch: epoch}
	}
}
