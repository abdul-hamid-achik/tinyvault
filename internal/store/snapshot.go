package store

import (
	"errors"
	"fmt"
	"io"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrInvalidSnapshot is returned by VerifySnapshot for a file that is not a
// usable TinyVault database.
var ErrInvalidSnapshot = errors.New("not a valid TinyVault database snapshot")

// Snapshot writes a consistent copy of the whole database to w.
//
// It runs inside a read transaction (bbolt's Tx.WriteTo), so the copy reflects
// one committed state even if another transaction commits meanwhile — unlike
// copying vault.db byte-for-byte, which can capture a half-written page.
// Secret payloads and key material stay encrypted in the copy; nothing is
// decrypted, so no unlock is needed.
func (s *BoltStore) Snapshot(w io.Writer) (int64, error) {
	var n int64
	err := s.db.View(func(tx *bolt.Tx) error {
		var werr error
		n, werr = tx.WriteTo(w)
		return werr
	})
	if err != nil {
		return n, fmt.Errorf("snapshot database: %w", err)
	}
	return n, nil
}

// VerifySnapshot opens path read-only and checks that it is a bbolt database
// carrying TinyVault's metadata. It proves a backup can be opened (and so
// restored) without unlocking or modifying it.
func VerifySnapshot(path string) error {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidSnapshot, path, err)
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketProjects, bucketSecrets} {
			if tx.Bucket(b) == nil {
				return fmt.Errorf("%w: %s: missing bucket %q", ErrInvalidSnapshot, path, b)
			}
		}
		return nil
	})
}
