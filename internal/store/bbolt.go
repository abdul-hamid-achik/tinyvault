package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// Sentinel errors.
var (
	ErrNotFound             = errors.New("not found")
	ErrProjectNotFound      = fmt.Errorf("project %w", ErrNotFound)
	ErrSecretNotFound       = fmt.Errorf("secret %w", ErrNotFound)
	ErrDuplicateProjectName = errors.New("project name already exists")
)

// Bucket names used in the bbolt database.
var (
	bucketMeta         = []byte("_meta")
	bucketConfig       = []byte("_config")
	bucketProjects     = []byte("projects")
	bucketSecrets      = []byte("secrets")
	bucketProjectNames = []byte("project_names")
	bucketAudit        = []byte("audit")
)

// BoltStore is the bbolt-backed implementation of Store.
type BoltStore struct {
	db *bolt.DB
}

// Compile-time interface check.
var _ Store = (*BoltStore)(nil)

// NewBoltStore opens (or creates) a bbolt database at path and ensures
// all required buckets exist. The file is created with 0600
// permissions.
func NewBoltStore(path string) (*BoltStore, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create dir: %w", err)
		}
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			bucketMeta,
			bucketConfig,
			bucketProjects,
			bucketSecrets,
			bucketProjectNames,
			bucketAudit,
		} {
			if _, bErr := tx.CreateBucketIfNotExists(b); bErr != nil {
				return fmt.Errorf("create bucket %s: %w", b, bErr)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}

	return &BoltStore{db: db}, nil
}

// Close closes the underlying bbolt database.
func (s *BoltStore) Close() error { return s.db.Close() }

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const metaKey = "vault_meta"

func (s *BoltStore) GetMeta() (*VaultMeta, error) {
	var meta VaultMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		v := b.Get([]byte(metaKey))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &meta)
	})
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

func (s *BoltStore) SetMeta(meta *VaultMeta) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshal meta: %w", err)
		}
		return tx.Bucket(bucketMeta).Put([]byte(metaKey), data)
	})
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

func (s *BoltStore) GetConfig(key string) (string, error) {
	var val string
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketConfig).Get([]byte(key))
		if v == nil {
			return ErrNotFound
		}
		val = string(v)
		return nil
	})
	return val, err
}

func (s *BoltStore) SetConfig(key, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Put([]byte(key), []byte(value))
	})
}

func (s *BoltStore) DeleteConfig(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Delete([]byte(key))
	})
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

func (s *BoltStore) CreateProject(project *Project) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		names := tx.Bucket(bucketProjectNames)
		if existing := names.Get([]byte(project.Name)); existing != nil {
			return ErrDuplicateProjectName
		}
		data, err := json.Marshal(project)
		if err != nil {
			return fmt.Errorf("marshal project: %w", err)
		}
		idKey := []byte(project.ID.String())
		if err := tx.Bucket(bucketProjects).Put(idKey, data); err != nil {
			return err
		}
		return names.Put([]byte(project.Name), idKey)
	})
}

func (s *BoltStore) GetProject(id uuid.UUID) (*Project, error) {
	var project Project
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketProjects).Get([]byte(id.String()))
		if v == nil {
			return ErrProjectNotFound
		}
		return json.Unmarshal(v, &project)
	})
	if err != nil {
		return nil, err
	}
	return &project, nil
}

func (s *BoltStore) GetProjectByName(name string) (*Project, error) {
	var project Project
	err := s.db.View(func(tx *bolt.Tx) error {
		idBytes := tx.Bucket(bucketProjectNames).Get([]byte(name))
		if idBytes == nil {
			return ErrProjectNotFound
		}
		v := tx.Bucket(bucketProjects).Get(idBytes)
		if v == nil {
			return ErrProjectNotFound
		}
		return json.Unmarshal(v, &project)
	})
	if err != nil {
		return nil, err
	}
	return &project, nil
}

func (s *BoltStore) ListProjects() ([]*Project, error) {
	out, err := s.listProjects(false)
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *BoltStore) ListProjectsIncludingDeleted() ([]*Project, error) {
	return s.listProjects(true)
}

func (s *BoltStore) ListProjectsFiltered(filter ProjectFilter) ([]*Project, error) {
	all, err := s.ListProjects()
	if err != nil {
		return nil, err
	}
	out := make([]*Project, 0, len(all))
	for _, p := range all {
		if filter.NameLike != "" && !matchLike(p.Name, filter.NameLike) {
			continue
		}
		if filter.DescriptionLike != "" && !matchLike(p.Description, filter.DescriptionLike) {
			continue
		}
		out = append(out, p)
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil, nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (s *BoltStore) listProjects(includeDeleted bool) ([]*Project, error) {
	var projects []*Project
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketProjects).ForEach(func(_, v []byte) error {
			var p Project
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			if includeDeleted || p.DeletedAt == nil {
				projects = append(projects, &p)
			}
			return nil
		})
	})
	return projects, err
}

func (s *BoltStore) UpdateProject(project *Project) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketProjects)
		idKey := []byte(project.ID.String())

		existing := bucket.Get(idKey)
		if existing == nil {
			return ErrProjectNotFound
		}

		var old Project
		if err := json.Unmarshal(existing, &old); err != nil {
			return fmt.Errorf("unmarshal old project: %w", err)
		}

		names := tx.Bucket(bucketProjectNames)
		if old.Name != project.Name {
			if dup := names.Get([]byte(project.Name)); dup != nil {
				return ErrDuplicateProjectName
			}
			if err := names.Delete([]byte(old.Name)); err != nil {
				return err
			}
			if err := names.Put([]byte(project.Name), idKey); err != nil {
				return err
			}
		}

		data, err := json.Marshal(project)
		if err != nil {
			return fmt.Errorf("marshal project: %w", err)
		}
		return bucket.Put(idKey, data)
	})
}

// RekeyProject atomically updates the project record and rewrites all of its
// secret entries verbatim, in one transaction. The caller (UnshareProject)
// has already rotated the DEK and re-encrypted every value; this persists
// the result all-or-nothing. Entries are written exactly as given (no
// version increment) since the plaintext values are unchanged.
func (s *BoltStore) RekeyProject(project *Project, secrets map[string]*SecretEntry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		projects := tx.Bucket(bucketProjects)
		idKey := []byte(project.ID.String())
		if projects.Get(idKey) == nil {
			return ErrProjectNotFound
		}
		pdata, err := json.Marshal(project)
		if err != nil {
			return fmt.Errorf("marshal project: %w", err)
		}
		if err := projects.Put(idKey, pdata); err != nil {
			return err
		}

		secretsBucket := tx.Bucket(bucketSecrets)
		for key, entry := range secrets {
			sdata, err := json.Marshal(entry)
			if err != nil {
				return fmt.Errorf("marshal secret %s: %w", key, err)
			}
			if err := secretsBucket.Put(secretKey(project.ID, key), sdata); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *BoltStore) DeleteProject(id uuid.UUID) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketProjects)
		idKey := []byte(id.String())

		v := bucket.Get(idKey)
		if v == nil {
			return ErrProjectNotFound
		}

		var project Project
		if err := json.Unmarshal(v, &project); err != nil {
			return fmt.Errorf("unmarshal project: %w", err)
		}

		now := time.Now().UTC()
		project.DeletedAt = &now

		data, err := json.Marshal(&project)
		if err != nil {
			return fmt.Errorf("marshal project: %w", err)
		}

		if err := bucket.Put(idKey, data); err != nil {
			return err
		}
		return tx.Bucket(bucketProjectNames).Delete([]byte(project.Name))
	})
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

func secretKey(projectID uuid.UUID, key string) []byte {
	return []byte(projectID.String() + "/" + key)
}

func secretPrefix(projectID uuid.UUID) string {
	return projectID.String() + "/"
}

func (s *BoltStore) SetSecret(projectID uuid.UUID, key string, entry *SecretEntry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketSecrets)
		compositeKey := secretKey(projectID, key)

		if existing := bucket.Get(compositeKey); existing != nil {
			var old SecretEntry
			if err := json.Unmarshal(existing, &old); err != nil {
				return fmt.Errorf("unmarshal existing secret: %w", err)
			}
			entry.Version = old.Version + 1
			entry.CreatedAt = old.CreatedAt
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal secret: %w", err)
		}
		return bucket.Put(compositeKey, data)
	})
}

func (s *BoltStore) GetSecret(projectID uuid.UUID, key string) (*SecretEntry, error) {
	var entry SecretEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSecrets).Get(secretKey(projectID, key))
		if v == nil {
			return ErrSecretNotFound
		}
		return json.Unmarshal(v, &entry)
	})
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func (s *BoltStore) DeleteSecret(projectID uuid.UUID, key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		compositeKey := secretKey(projectID, key)
		bucket := tx.Bucket(bucketSecrets)
		if bucket.Get(compositeKey) == nil {
			return ErrSecretNotFound
		}
		return bucket.Delete(compositeKey)
	})
}

func (s *BoltStore) ListSecretKeys(projectID uuid.UUID) ([]string, error) {
	return s.scanSecretKeys(projectID, SecretFilter{})
}

func (s *BoltStore) ListSecretKeysFiltered(projectID uuid.UUID, filter SecretFilter) ([]string, error) {
	return s.scanSecretKeys(projectID, filter)
}

func (s *BoltStore) scanSecretKeys(projectID uuid.UUID, filter SecretFilter) ([]string, error) {
	prefix := []byte(secretPrefix(projectID))
	var keys []string
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecrets).Cursor()
		for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
			entry, err := decodeSecretValue(v)
			if err != nil {
				return err
			}
			name := strings.TrimPrefix(string(k), string(prefix))
			if !secretMatchesFilter(name, entry, filter) {
				continue
			}
			keys = append(keys, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)
	return applyLimitOffset(keys, filter.Limit, filter.Offset), nil
}

func (s *BoltStore) ListSecrets(projectID uuid.UUID) (map[string]*SecretEntry, error) {
	prefix := []byte(secretPrefix(projectID))
	secrets := make(map[string]*SecretEntry)
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecrets).Cursor()
		for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
			entry, err := decodeSecretValue(v)
			if err != nil {
				return err
			}
			secrets[strings.TrimPrefix(string(k), string(prefix))] = entry
		}
		return nil
	})
	return secrets, err
}

// ListSecretsByProject scans every project's secrets, applying the
// filter. This is O(P*K) where P = project count and K = keys per
// project; for the expected scale (low thousands of secrets total)
// this is fine and avoids the maintenance cost of a separate index.
func (s *BoltStore) ListSecretsByProject(filter SecretFilter) ([]SecretLocation, error) {
	projects, err := s.ListProjects()
	if err != nil {
		return nil, err
	}
	var out []SecretLocation
	for _, p := range projects {
		err := s.db.View(func(tx *bolt.Tx) error {
			prefix := []byte(secretPrefix(p.ID))
			c := tx.Bucket(bucketSecrets).Cursor()
			for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
				entry, err := decodeSecretValue(v)
				if err != nil {
					return err
				}
				name := strings.TrimPrefix(string(k), string(prefix))
				if !secretMatchesFilter(name, entry, filter) {
					continue
				}
				out = append(out, SecretLocation{
					ProjectID:   p.ID,
					ProjectName: p.Name,
					Key:         name,
					Version:     entry.Version,
					UpdatedAt:   entry.UpdatedAt,
				})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProjectName != out[j].ProjectName {
			return out[i].ProjectName < out[j].ProjectName
		}
		return out[i].Key < out[j].Key
	})
	return applyLimitOffset(out, filter.Limit, filter.Offset), nil
}

func (s *BoltStore) CountSecrets(projectID uuid.UUID) (int, error) {
	prefix := []byte(secretPrefix(projectID))
	count := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecrets).Cursor()
		for k, _ := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, _ = c.Next() {
			count++
		}
		return nil
	})
	return count, err
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func (s *BoltStore) AppendAudit(entry *AuditEntry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := []byte(fmt.Sprintf("%s_%s",
			entry.Timestamp.UTC().Format(time.RFC3339Nano),
			uuid.New().String()))
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal audit entry: %w", err)
		}
		return tx.Bucket(bucketAudit).Put(key, data)
	})
}

func (s *BoltStore) ListAudit(limit int) ([]*AuditEntry, error) {
	return s.ListAuditFiltered(AuditFilter{Limit: limit})
}

func (s *BoltStore) ListAuditFiltered(filter AuditFilter) ([]*AuditEntry, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	entries := []*AuditEntry{}
	skipped := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudit).Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if limit > 0 && len(entries) >= limit {
				break
			}
			var entry AuditEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			if !auditMatchesFilter(&entry, filter) {
				continue
			}
			if filter.Offset > 0 && skipped < filter.Offset {
				skipped++
				continue
			}
			entries = append(entries, &entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})
	return entries, nil
}

func (s *BoltStore) CountAudit() (int, error) {
	count := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudit).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			count++
		}
		return nil
	})
	return count, err
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func decodeSecretValue(data []byte) (*SecretEntry, error) {
	var entry SecretEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("unmarshal secret: %w", err)
	}
	return &entry, nil
}

func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i, c := range prefix {
		if b[i] != c {
			return false
		}
	}
	return true
}

func secretMatchesFilter(name string, entry *SecretEntry, f SecretFilter) bool {
	if f.Prefix != "" && !strings.HasPrefix(name, f.Prefix) {
		return false
	}
	if f.NameLike != "" && !matchLike(name, f.NameLike) {
		return false
	}
	if !f.UpdatedAfter.IsZero() && entry.UpdatedAt.Before(f.UpdatedAfter) {
		return false
	}
	if !f.UpdatedBefore.IsZero() && entry.UpdatedAt.After(f.UpdatedBefore) {
		return false
	}
	if f.VersionAtLeast > 0 && entry.Version < f.VersionAtLeast {
		return false
	}
	return true
}

func auditMatchesFilter(e *AuditEntry, f AuditFilter) bool {
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if f.ResourceType != "" && e.ResourceType != f.ResourceType {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Timestamp.After(f.Until) {
		return false
	}
	return true
}

// matchLike applies a SQL-LIKE-style glob with '*' as the only
// wildcard. We do not implement `%` or character classes; the
// in-memory LIKE is intentionally minimal.
func matchLike(s, pattern string) bool {
	// Convert to a small state machine: split on '*' and walk.
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return s == pattern
	}
	// prefix must match the first part
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	// suffix must match the last part
	if !strings.HasSuffix(s, parts[len(parts)-1]) {
		return false
	}
	// middle parts must appear in order
	rest := s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		idx := strings.Index(rest, parts[i])
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(parts[i]):]
	}
	return true
}

// applyLimitOffset slices `in` to a window of `limit` items starting
// at `offset`. It returns just the slice because the operation cannot
// fail.
func applyLimitOffset[T any](in []T, limit, offset int) []T {
	out := in
	if offset > 0 {
		if offset >= len(out) {
			return nil
		}
		out = out[offset:]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ensureDir is intentionally absent; NewBoltStore uses os.MkdirAll
// directly.
