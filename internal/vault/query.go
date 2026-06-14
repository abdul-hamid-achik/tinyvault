package vault

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
)

// SecretRef is a public, lightweight handle on a single secret.
// Returned by relational queries; never includes the value.
type SecretRef struct {
	Project   string
	Key       string
	Version   int
	UpdatedAt time.Time
}

// SecretSearchQuery is the public query type for SecretRefs.
//
// All fields are optional; a zero-value query returns every secret
// in the vault (limited to 1000 by default).
type SecretSearchQuery struct {
	Project    string    // restrict to a project name (empty = all)
	Prefix     string    // key prefix
	NameLike   string    // SQL-like pattern with '*' wildcard
	Since      time.Time // only secrets updated at or after this time
	Until      time.Time // only secrets updated at or before this time
	MinVersion int       // only secrets with Version >= this
	Limit      int       // default 1000
	Offset     int
}

// Search returns every secret whose metadata matches the query, in
// (project, key) order. The vault does not need to be unlocked; this
// method only reads metadata, never decrypted values.
func (v *Vault) Search(q SecretSearchQuery) ([]SecretRef, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 1000
	}

	if q.Project != "" {
		// Project-scoped search uses the cheaper path.
		project, err := v.store.GetProjectByName(q.Project)
		if err != nil {
			return nil, mapStoreError(err)
		}
		keys, err := v.store.ListSecretKeysFiltered(project.ID, store.SecretFilter{
			Prefix:         q.Prefix,
			NameLike:       q.NameLike,
			UpdatedAfter:   q.Since,
			UpdatedBefore:  q.Until,
			VersionAtLeast: q.MinVersion,
			Limit:          limit,
			Offset:         q.Offset,
		})
		if err != nil {
			return nil, err
		}
		// We need the metadata (version + updated_at), so we look up
		// each key. For a project-scoped query this is bounded by
		// Limit, so the cost is O(Limit) reads.
		out := make([]SecretRef, 0, len(keys))
		for _, k := range keys {
			entry, err := v.store.GetSecret(project.ID, k)
			if err != nil {
				continue
			}
			out = append(out, SecretRef{
				Project:   q.Project,
				Key:       k,
				Version:   entry.Version,
				UpdatedAt: entry.UpdatedAt,
			})
		}
		return out, nil
	}

	// Cross-project search.
	locs, err := v.store.ListSecretsByProject(store.SecretFilter{
		Prefix:         q.Prefix,
		NameLike:       q.NameLike,
		UpdatedAfter:   q.Since,
		UpdatedBefore:  q.Until,
		VersionAtLeast: q.MinVersion,
		Limit:          limit,
		Offset:         q.Offset,
	})
	if err != nil {
		return nil, err
	}
	out := make([]SecretRef, 0, len(locs))
	for _, l := range locs {
		out = append(out, SecretRef{
			Project:   l.ProjectName,
			Key:       l.Key,
			Version:   l.Version,
			UpdatedAt: l.UpdatedAt,
		})
	}
	return out, nil
}

// CountSecrets returns the number of secrets in a project.
func (v *Vault) CountSecrets(projectName string) (int, error) {
	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return 0, mapStoreError(err)
	}
	return v.store.CountSecrets(project.ID)
}

// SearchProjects returns projects whose name or description match the
// query. Both NameLike and DescriptionLike are SQL-like patterns
// using '*' as the only wildcard.
func (v *Vault) SearchProjects(nameLike, descriptionLike string, limit int) ([]string, error) {
	projects, err := v.store.ListProjectsFiltered(store.ProjectFilter{
		NameLike:        nameLike,
		DescriptionLike: descriptionLike,
		Limit:           limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(projects))
	for _, p := range projects {
		out = append(out, p.Name)
	}
	return out, nil
}

// ListAudit returns the most recent audit entries, optionally filtered.
// A zero-value AuditFilter returns the most recent 100.
func (v *Vault) ListAudit(filter store.AuditFilter) ([]*store.AuditEntry, error) {
	return v.store.ListAuditFiltered(filter)
}

// ListProjectNamesByPrefix returns project names that start with
// prefix. Convenience wrapper used by `tvault projects list` and the
// MCP layer.
func (v *Vault) ListProjectNamesByPrefix(prefix string) ([]string, error) {
	if prefix == "" {
		projects, err := v.ListProjects()
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(projects))
		for _, p := range projects {
			names = append(names, p.Name)
		}
		return names, nil
	}
	return v.SearchProjects(prefix, "", 0)
}

// ProjectByID is a low-level accessor used by sync to compute diffs
// without going through name lookup. It returns ErrProjectNotFound if
// the id is unknown.
func (v *Vault) ProjectByID(id uuid.UUID) (*store.Project, error) {
	p, err := v.store.GetProject(id)
	if err != nil {
		return nil, mapStoreError(err)
	}
	return p, nil
}

// ProjectCount returns the number of non-deleted projects.
func (v *Vault) ProjectCount() int {
	all, err := v.store.ListProjects()
	if err != nil {
		return 0
	}
	return len(all)
}

// ProjectSnapshot is a read-only summary of a project. Used by the
// MCP layer to surface the same fields as a SQL projection.
type ProjectSnapshot struct {
	Name        string
	Description string
	SecretCount int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SnapshotProjects returns a list of ProjectSnapshot, one per project,
// with each project's secret count. Cheap on bbolt: one cursor per
// project, no decryption.
func (v *Vault) SnapshotProjects() ([]ProjectSnapshot, error) {
	projects, err := v.store.ListProjects()
	if err != nil {
		return nil, err
	}
	out := make([]ProjectSnapshot, 0, len(projects))
	for _, p := range projects {
		count, cerr := v.store.CountSecrets(p.ID)
		if cerr != nil {
			// Skip this project on error; do not fail the whole snapshot.
			continue
		}
		out = append(out, ProjectSnapshot{
			Name:        p.Name,
			Description: p.Description,
			SecretCount: count,
			CreatedAt:   p.CreatedAt,
			UpdatedAt:   p.UpdatedAt,
		})
	}
	return out, nil
}

// errSearchEmpty is a sentinel returned when a Search query yields no
// rows. Callers can errors.Is against it if they want a different code
// path for "no results" vs "error".
var errSearchEmpty = fmt.Errorf("no results")

// IsEmptyResult reports whether err indicates an empty search result.
// Reserved for future use; currently always returns false because
// Search returns an empty slice on no results, not an error.
func IsEmptyResult(err error) bool {
	return err != nil && err.Error() == errSearchEmpty.Error()
}
