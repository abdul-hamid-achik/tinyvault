package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
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

// Sentinel errors returned by store operations.
var (
	ErrNotFound             = errors.New("not found")
	ErrProjectNotFound      = fmt.Errorf("project %w", ErrNotFound)
	ErrSecretNotFound       = fmt.Errorf("secret %w", ErrNotFound)
	ErrDuplicateProjectName = errors.New("project name already exists")
)

// BoltStore implements Store using bbolt.
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore opens (or creates) a bbolt database at the given path and
// ensures all required buckets exist. The file is created with 0600 permissions.
func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	// Create all buckets if they do not exist.
	if err = db.Update(func(tx *bolt.Tx) error {
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
		db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}

	return &BoltStore{db: db}, nil
}

// Close closes the underlying bbolt database.
func (s *BoltStore) Close() error {
	return s.db.Close()
}

// ---------------------------------------------------------------------------
// Vault metadata
// ---------------------------------------------------------------------------

const metaKey = "vault_meta"

// GetMeta returns the vault metadata, or ErrNotFound if not set.
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

// SetMeta stores the vault metadata.
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

// GetConfig returns the config value for the given key, or ErrNotFound.
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

// SetConfig stores a config key-value pair.
func (s *BoltStore) SetConfig(key, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Put([]byte(key), []byte(value))
	})
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// CreateProject stores a new project. It returns ErrDuplicateProjectName if a
// project with the same name already exists (including soft-deleted projects
// whose name index entry has not been cleared).
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

// GetProject retrieves a project by its UUID.
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

// GetProjectByName retrieves a project by name using the name index.
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

// ListProjects returns all non-deleted projects.
func (s *BoltStore) ListProjects() ([]*Project, error) {
	var projects []*Project
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketProjects).ForEach(func(_, v []byte) error {
			var p Project
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			if p.DeletedAt == nil {
				projects = append(projects, &p)
			}
			return nil
		})
	})
	return projects, err
}

// UpdateProject updates an existing project in-place. It also updates the name
// index if the name has changed.
func (s *BoltStore) UpdateProject(project *Project) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketProjects)
		idKey := []byte(project.ID.String())

		// Load the existing project so we can detect name changes.
		existing := bucket.Get(idKey)
		if existing == nil {
			return ErrProjectNotFound
		}

		var old Project
		if err := json.Unmarshal(existing, &old); err != nil {
			return fmt.Errorf("unmarshal old project: %w", err)
		}

		// Handle name change: remove old index entry, check for conflicts, add new.
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

// DeleteProject performs a soft-delete by setting DeletedAt on the project. It
// also removes the name index entry so the name can be reused.
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

		// Remove name index so the name can be reused.
		return tx.Bucket(bucketProjectNames).Delete([]byte(project.Name))
	})
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// secretKey builds the composite key: "projectUUID/secretKey".
func secretKey(projectID uuid.UUID, key string) []byte {
	return []byte(projectID.String() + "/" + key)
}

// secretPrefix returns the prefix for all secrets of a project.
func secretPrefix(projectID uuid.UUID) string {
	return projectID.String() + "/"
}

// SetSecret stores or updates a secret. If the key already exists, the version
// is auto-incremented (upsert semantics).
func (s *BoltStore) SetSecret(projectID uuid.UUID, key string, entry *SecretEntry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketSecrets)
		compositeKey := secretKey(projectID, key)

		// Check for existing entry to handle version auto-increment.
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

// GetSecret retrieves a single secret by project ID and key.
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

// ListSecretKeys returns the secret key names for a given project.
func (s *BoltStore) ListSecretKeys(projectID uuid.UUID) ([]string, error) {
	prefix := secretPrefix(projectID)
	var keys []string
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecrets).Cursor()
		prefixBytes := []byte(prefix)
		for k, _ := c.Seek(prefixBytes); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
			keys = append(keys, strings.TrimPrefix(string(k), prefix))
		}
		return nil
	})
	return keys, err
}

// ListSecrets returns all secrets for a given project as a map of key -> entry.
func (s *BoltStore) ListSecrets(projectID uuid.UUID) (map[string]*SecretEntry, error) {
	prefix := secretPrefix(projectID)
	secrets := make(map[string]*SecretEntry)
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecrets).Cursor()
		prefixBytes := []byte(prefix)
		for k, v := c.Seek(prefixBytes); k != nil && strings.HasPrefix(string(k), prefix); k, v = c.Next() {
			var entry SecretEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			name := strings.TrimPrefix(string(k), prefix)
			secrets[name] = &entry
		}
		return nil
	})
	return secrets, err
}

// DeleteSecret removes a secret by project ID and key.
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

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// AppendAudit appends an audit entry. Entries are keyed by timestamp + UUID
// for ordering and uniqueness.
func (s *BoltStore) AppendAudit(entry *AuditEntry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := fmt.Sprintf("%s_%s", entry.Timestamp.UTC().Format(time.RFC3339Nano), uuid.New().String())
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal audit entry: %w", err)
		}
		return tx.Bucket(bucketAudit).Put([]byte(key), data)
	})
}

// ListAudit returns the most recent audit entries, up to the given limit.
// Entries are returned in reverse chronological order (newest first).
func (s *BoltStore) ListAudit(limit int) ([]*AuditEntry, error) {
	var entries []*AuditEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudit).Cursor()

		// Collect all entries (keys are time-sorted lexicographically).
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if limit > 0 && len(entries) >= limit {
				break
			}
			var entry AuditEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			entries = append(entries, &entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort newest first (should already be via cursor, but be explicit).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, err
}
