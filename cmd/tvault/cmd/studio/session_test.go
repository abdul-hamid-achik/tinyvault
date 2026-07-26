package studio

import (
	"errors"
	"sync"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// TestSessionDoesNotHoldTheVaultLock is the reason this Session type exists.
// bbolt's lock is process-wide, so a studio that kept the database open would
// make every other tvault invocation on the machine fail for the whole
// interactive session.
func TestSessionDoesNotHoldTheVaultLock(t *testing.T) {
	sess := newScratchSession(t)

	// Do real work through the session first, so the check runs against a
	// session that has actually opened the vault at least once.
	if _, err := loadProjects(sess); err != nil {
		t.Fatalf("loadProjects: %v", err)
	}
	if _, err := loadStatus(sess); err != nil {
		t.Fatalf("loadStatus: %v", err)
	}

	other, err := vault.Open(sess.Dir())
	if err != nil {
		t.Fatalf("vault was still locked while a studio session was live: %v", err)
	}
	if err := other.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestSessionRevealUsesTheCachedKEK covers the value path: a reveal must work
// without re-deriving from a passphrase.
func TestSessionRevealUsesTheCachedKEK(t *testing.T) {
	sess := newScratchSession(t)
	val, err := revealSecret(sess, "webapp", "STRIPE_KEY")
	if err != nil {
		t.Fatalf("revealSecret: %v", err)
	}
	if val != "sk_live_abc123" {
		t.Errorf("value = %q, want the seeded secret", val)
	}
}

// TestSessionLockBlocksValueReads keeps the in-app lock ('l') meaningful: after
// it, a reveal must fail rather than serve a value from a stale KEK.
func TestSessionLockBlocksValueReads(t *testing.T) {
	sess := newScratchSession(t)
	if !sess.Unlocked() {
		t.Fatal("a freshly seeded session should hold key material")
	}

	sess.Lock()
	if sess.Unlocked() {
		t.Error("Unlocked() should be false after Lock()")
	}
	if _, err := revealSecret(sess, "webapp", "STRIPE_KEY"); err == nil {
		t.Error("a reveal after Lock() must fail, not serve a value")
	}

	// Metadata still works locked — that is what keeps the studio browsable
	// before the user unlocks.
	if _, err := loadProjects(sess); err != nil {
		t.Errorf("project metadata should load while locked, got %v", err)
	}
}

// TestSessionUnlockAfterLockRestoresReads covers the in-app 'u' flow.
func TestSessionUnlockAfterLockRestoresReads(t *testing.T) {
	sess := newScratchSession(t)
	sess.Lock()

	if err := sess.Unlock("test-pass"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	val, err := revealSecret(sess, "webapp", "STRIPE_KEY")
	if err != nil {
		t.Fatalf("revealSecret after re-unlock: %v", err)
	}
	if val != "sk_live_abc123" {
		t.Errorf("value = %q, want the seeded secret", val)
	}
}

func TestSessionUnlockWrongPassphrase(t *testing.T) {
	sess := newScratchSession(t)
	sess.Lock()

	err := sess.Unlock("not-the-passphrase")
	if err == nil {
		t.Fatal("a wrong passphrase must be rejected")
	}
	if !errors.Is(err, vault.ErrWrongPassphrase) {
		t.Errorf("error = %v, want vault.ErrWrongPassphrase", err)
	}
	if sess.Unlocked() {
		t.Error("a failed unlock must not leave the session holding key material")
	}
}

// TestSessionCloseIsIdempotent covers the deferred Close on every exit path,
// which may run after an in-app lock already zeroed the KEK.
func TestSessionCloseIsIdempotent(t *testing.T) {
	sess := newScratchSession(t)
	sess.Close()
	sess.Close()
	if sess.Unlocked() {
		t.Error("Close() must leave the session locked")
	}
}

// TestSessionConcurrentLoads exercises the mutex: Bubble Tea runs each tea.Cmd
// on its own goroutine, so several loads can hit the session at once, and bbolt
// allows only one writer process at a time.
func TestSessionConcurrentLoads(t *testing.T) {
	sess := newScratchSession(t)

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n*3)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := loadProjects(sess); err != nil {
				errs <- err
			}
			if _, err := loadSecrets(sess, "webapp"); err != nil {
				errs <- err
			}
			if _, err := revealSecret(sess, "webapp", "STRIPE_KEY"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent load failed: %v", err)
	}
}
