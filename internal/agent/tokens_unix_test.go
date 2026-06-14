//go:build unix

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// startTokenAgent starts a --require-token agent over a fresh vault (default +
// staging projects) using the given token file, returning the dir and a stop
// func that uses stopTok (an unrestricted token) to shut the agent down.
func startTokenAgent(t *testing.T, tokenFile, stopTok string) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tvt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_ = os.Chmod(dir, 0o700)

	v, err := vault.Create(dir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if serr := v.SetSecret("default", "DB_URL", "postgres://x"); serr != nil {
		t.Fatal(serr)
	}
	if _, perr := v.CreateProject("staging", ""); perr != nil {
		t.Fatal(perr)
	}
	if serr := v.SetSecret("staging", "STG", "s"); serr != nil {
		t.Fatal(serr)
	}
	kek, err := v.KEK()
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Start(Options{
			Dir: dir, KEK: kek, Project: "default", Idle: 0,
			RequireToken: true, TokenFile: tokenFile,
			OnReady: func(s string, _ int) { ready <- s },
		})
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("token agent start: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("token agent did not become ready")
	}
	return dir, func() {
		if c, e := Dial(dir, time.Second); e == nil {
			_ = c.WithToken(stopTok).Stop()
		}
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
			t.Error("token agent did not shut down")
		}
	}
}

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadTokens(t *testing.T) {
	path := writeTokenFile(t, "# comment\n\nfulltok\nstgtok:staging\n  spaced  \n")
	toks, err := loadTokens(path)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	if len(toks) != 3 {
		t.Fatalf("want 3 tokens, got %d", len(toks))
	}
	if s, ok := toks[tokenHash("fulltok")]; !ok || s.project != "" {
		t.Errorf("fulltok should be unrestricted, got %+v ok=%v", s, ok)
	}
	if s, ok := toks[tokenHash("stgtok")]; !ok || s.project != "staging" {
		t.Errorf("stgtok should be scoped to staging, got %+v ok=%v", s, ok)
	}
}

func TestLoadTokensRejectsLoosePermsAndEmpty(t *testing.T) {
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.WriteFile(loose, []byte("t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTokens(loose); err == nil {
		t.Error("a group/world-readable token file must be rejected")
	}
	empty := writeTokenFile(t, "# only comments\n\n")
	if _, err := loadTokens(empty); err == nil {
		t.Error("an empty token file must be rejected")
	}
}

func TestRequireTokenDeniesAndAllows(t *testing.T) {
	tf := writeTokenFile(t, "fulltok\n")
	dir, stop := startTokenAgent(t, tf, "fulltok")
	defer stop()

	// Token-less → denied.
	if _, err := Dial(dir, time.Second); err == nil {
		c, _ := Dial(dir, time.Second)
		if _, gerr := c.Get("default", "DB_URL"); gerr == nil {
			t.Error("token-less get must be denied in --require-token mode")
		}
	}
	// Valid token → served.
	c, _ := Dial(dir, time.Second)
	if v, gerr := c.WithToken("fulltok").Get("default", "DB_URL"); gerr != nil || v != "postgres://x" {
		t.Errorf("valid-token get = %q (err %v)", v, gerr)
	}
	// Unknown token → denied.
	c2, _ := Dial(dir, time.Second)
	if _, gerr := c2.WithToken("nope").Get("default", "DB_URL"); gerr == nil {
		t.Error("unknown token must be denied")
	}
}

func TestTokenScopeEnforced(t *testing.T) {
	tf := writeTokenFile(t, "fulltok\nstgtok:staging\n")
	dir, stop := startTokenAgent(t, tf, "fulltok")
	defer stop()

	// staging-scoped token reads staging.
	c, _ := Dial(dir, time.Second)
	if v, gerr := c.WithToken("stgtok").Get("staging", "STG"); gerr != nil || v != "s" {
		t.Errorf("in-scope get = %q (err %v)", v, gerr)
	}
	// ...but not default (out of scope).
	c2, _ := Dial(dir, time.Second)
	if _, gerr := c2.WithToken("stgtok").Get("default", "DB_URL"); gerr == nil {
		t.Error("out-of-scope get must be denied")
	}
	// getall out of scope denied too.
	c3, _ := Dial(dir, time.Second)
	if _, _, gerr := c3.WithToken("stgtok").GetAll("default"); gerr == nil {
		t.Error("out-of-scope getall must be denied")
	}
	// A scoped token must not be able to stop the agent (operator-only control).
	c4, _ := Dial(dir, time.Second)
	if serr := c4.WithToken("stgtok").Stop(); serr == nil {
		t.Error("a scoped token must not be able to stop the agent")
	}
}

func TestTokenAuditNoLeak(t *testing.T) {
	const tok = "supersecret-token-value"
	tf := writeTokenFile(t, tok+"\n")
	dir, stop := startTokenAgent(t, tf, tok)
	defer stop()

	c, _ := Dial(dir, time.Second)
	if _, err := c.WithToken(tok).Get("default", "DB_URL"); err != nil {
		t.Fatalf("get: %v", err)
	}

	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	entries, err := v.ListAudit(store.AuditFilter{Action: "secret.read"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Metadata["via"] != "agent" {
			continue
		}
		found = true
		id, _ := e.Metadata["token_id"].(string)
		if len(id) != 8 {
			t.Errorf("token_id should be an 8-char hash prefix, got %q", id)
		}
		if strings.Contains(id, tok) {
			t.Error("token_id leaked the raw token")
		}
	}
	if !found {
		t.Fatal("expected a via:agent audit entry")
	}
	// The raw token must appear in NO audit entry.
	if entries := mustAuditAll(t, v); strings.Contains(entries, tok) {
		t.Error("the raw token leaked into the audit log")
	}
}

func mustAuditAll(t *testing.T, v *vault.Vault) string {
	t.Helper()
	es, err := v.ListAudit(store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range es {
		for k, val := range e.Metadata {
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(toStr(val))
			b.WriteString(" ")
		}
	}
	return b.String()
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestTokenReloadOnSIGHUP(t *testing.T) {
	path := writeTokenFile(t, "oldtok\nfulltok\n")
	dir, stop := startTokenAgent(t, path, "fulltok")
	defer stop()

	getWith := func(tok string) error {
		c, _ := Dial(dir, time.Second)
		_, err := c.WithToken(tok).Get("default", "DB_URL")
		return err
	}
	if err := getWith("oldtok"); err != nil {
		t.Fatalf("oldtok should work initially: %v", err)
	}

	// Revoke oldtok, add newtok; reload via SIGHUP (the agent runs in-process).
	if err := os.WriteFile(path, []byte("newtok\nfulltok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	// Wait (bounded) for the reload to take effect: oldtok becomes denied.
	revoked := false
	for i := 0; i < 100; i++ {
		if getWith("oldtok") != nil {
			revoked = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !revoked {
		t.Error("oldtok should be denied after SIGHUP reload")
	}
	if err := getWith("newtok"); err != nil {
		t.Errorf("newtok should work after reload: %v", err)
	}

	// A bad reload (empty file) keeps the current set: newtok still works.
	if err := os.WriteFile(path, []byte("# emptied\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(150 * time.Millisecond)
	if err := getWith("newtok"); err != nil {
		t.Errorf("a failed reload must keep the prior token set; newtok broke: %v", err)
	}
}

// TestRequireTokenNeedsValidFile guards the start-time validation.
func TestRequireTokenNeedsValidFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "tvt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0o700)
	v, _ := vault.Create(dir, "pw")
	kek, _ := v.KEK()
	_ = v.Close()
	// require-token with a missing token file → Start fails (no socket served).
	err = Start(Options{Dir: dir, KEK: kek, RequireToken: true, TokenFile: filepath.Join(dir, "nope")})
	if err == nil {
		t.Error("require-token with an unreadable token file must fail to start")
	}
}
