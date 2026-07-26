package studio

import (
	"sync"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// Session owns the studio's access to the vault.
//
// # Why it holds a KEK and not an open vault
//
// bbolt takes an exclusive process-wide lock, so a studio that kept the
// database open would block every other tvault invocation on the machine for
// the whole session — the same defect that made a long-lived `tvault run` take
// the vault down globally. The studio therefore caches only the KEK and reopens
// the vault per operation, exactly as the local agent does (see
// internal/agent's KEK-only invariant). Re-unlocking with a cached KEK skips
// Argon2id, so a reopen costs a file open rather than ~200ms of key derivation.
//
// A Session is safe for concurrent use: Bubble Tea runs tea.Cmd functions on
// their own goroutines, so several loads can be in flight at once, and bbolt
// permits only one writer process at a time. The mutex serializes them.
type Session struct {
	dir string

	mu  sync.Mutex
	kek []byte // nil while locked
}

// NewSession returns a Session for the vault at dir.
//
// kek may be nil, which means the studio launches locked and the user unlocks
// in-app. When non-nil the Session takes ownership of the slice and zeros it on
// Lock or Close, so the caller must not reuse or zero it.
func NewSession(dir string, kek []byte) *Session {
	return &Session{dir: dir, kek: kek}
}

// Dir returns the vault directory backing this session.
func (s *Session) Dir() string { return s.dir }

// Unlocked reports whether the session holds key material.
func (s *Session) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.kek) > 0
}

// with opens the vault, unlocks it with the cached KEK when there is one, runs
// fn, and closes the vault before returning — so the bbolt lock is held only
// for the duration of fn.
//
// When the session is locked the vault is passed to fn still locked, letting
// metadata-only callers (status, project list) work without key material while
// value reads fail with vault.ErrLocked as they should.
func (s *Session) with(fn func(*vault.Vault) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := vault.Open(s.dir)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	if len(s.kek) > 0 {
		if err := v.UnlockWithKEK(s.kek); err != nil {
			return err
		}
	}
	return fn(v)
}

// Unlock derives the KEK from a passphrase and caches it for the session. It is
// the only path that pays the Argon2id cost; every later operation reuses the
// cached KEK.
func (s *Session) Unlock(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := vault.Open(s.dir)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	if uerr := v.Unlock(passphrase); uerr != nil {
		return uerr
	}
	kek, err := v.KEK()
	if err != nil {
		return err
	}
	// Replace rather than append: a second unlock must not leave the previous
	// KEK reachable.
	crypto.ZeroBytes(s.kek)
	s.kek = kek
	return nil
}

// Lock zeros the cached KEK. Subsequent value reads fail with vault.ErrLocked
// until Unlock is called again.
func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	crypto.ZeroBytes(s.kek)
	s.kek = nil
}

// Close releases the session's key material. It is idempotent, and callers must
// invoke it on every exit path — including a panic — so the KEK does not
// outlive the studio.
func (s *Session) Close() { s.Lock() }
