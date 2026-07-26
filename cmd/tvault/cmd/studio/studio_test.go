package studio

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// newScratchSession creates a temp vault populated with two projects and a
// handful of secrets + audit entries, then CLOSES it and returns a Session
// holding its KEK. It is the shared fixture for the data and model tests.
//
// Closing matters: the studio reopens the vault per operation, so a fixture that
// kept it open would collide with bbolt's exclusive lock and every Session call
// would fail with ErrVaultBusy.
func newScratchSession(t *testing.T) *Session {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Create(dir, "test-pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}

	if _, err := v.CreateProject("webapp", "the web app"); err != nil {
		t.Fatalf("create webapp: %v", err)
	}
	if _, err := v.CreateProject("api", "the api"); err != nil {
		t.Fatalf("create api: %v", err)
	}
	if err := v.SetCurrentProject("webapp"); err != nil {
		t.Fatalf("set current: %v", err)
	}
	for k, val := range map[string]string{
		"STRIPE_KEY": "sk_live_abc123",
		"DB_URL":     "postgres://localhost/web",
		"AWS_SECRET": "wJalrXUtnFEMI",
	} {
		if err := v.SetSecret("webapp", k, val); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	if err := v.SetSecret("api", "TOKEN", "tok_xyz"); err != nil {
		t.Fatalf("set TOKEN: %v", err)
	}

	now := time.Now().UTC()
	for _, e := range []*store.AuditEntry{
		{Action: "set", ResourceType: "secret", ResourceName: "STRIPE_KEY", Timestamp: now.Add(-2 * time.Minute)},
		{Action: "unlock", ResourceType: "vault", ResourceName: "webapp", Timestamp: now.Add(-1 * time.Minute)},
	} {
		if err := v.AppendAudit(e); err != nil {
			t.Fatalf("append audit: %v", err)
		}
	}

	kek, err := v.KEK()
	if err != nil {
		t.Fatalf("extract KEK: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("close scratch vault: %v", err)
	}
	sess := NewSession(dir, kek)
	t.Cleanup(sess.Close)
	return sess
}

// mustLoadStatus loads the status pane's data, failing the test on error.
func mustLoadStatus(t *testing.T, s *Session) statusData {
	t.Helper()
	sd, err := loadStatus(s)
	if err != nil {
		t.Fatalf("loadStatus: %v", err)
	}
	return sd
}

// scratchGet reads one value straight from the vault, so a test can assert what
// a studio mutation actually persisted rather than trusting the model's state.
func scratchGet(t *testing.T, s *Session, project, key string) (string, error) {
	t.Helper()
	var val string
	err := s.with(func(v *vault.Vault) error {
		var e error
		val, e = v.GetSecret(project, key)
		return e
	})
	return val, err
}

// scratchEdit opens the session's vault for direct setup a test needs before
// exercising the studio (creating a group, adding a key, and so on).
func scratchEdit(t *testing.T, s *Session, fn func(*vault.Vault) error) {
	t.Helper()
	if err := s.with(fn); err != nil {
		t.Fatalf("scratch edit: %v", err)
	}
}

// newReadyModel builds a model the way the program would after the first
// window-size + data-load round trip, ready for synthetic key events.
func newReadyModel(t *testing.T, v *Session, opts Options) Model {
	t.Helper()
	m := New(v, opts)
	m.anim = false // deterministic tests: no frame loop
	m = update(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = update(t, m, statusLoadedMsg(mustLoadStatus(t, v)))
	projects, err := loadProjects(v)
	if err != nil {
		t.Fatalf("load projects: %v", err)
	}
	m = update(t, m, projectsLoadedMsg{projects: projects})
	secs, err := loadSecrets(v, m.viewProject)
	if err != nil {
		t.Fatalf("load secrets: %v", err)
	}
	m = update(t, m, secretsLoadedMsg{project: m.viewProject, refs: secs})
	audit, err := loadAudit(v, 100)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	m = update(t, m, auditLoadedMsg{entries: audit})
	return m
}

// update runs one Update and type-asserts back to the concrete Model.
func update(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	next, _ := m.Update(msg)
	got, ok := next.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want tui.Model", next)
	}
	return got
}

// keyPress builds a KeyPressMsg for a single rune or named key.
func keyPress(s string) tea.KeyPressMsg {
	if len(s) == 1 {
		return tea.KeyPressMsg{Code: rune(s[0]), Text: s}
	}
	return tea.KeyPressMsg{Code: namedKeyCode(s)}
}

func namedKeyCode(s string) rune {
	switch s {
	case "enter":
		return tea.KeyEnter
	case "esc":
		return tea.KeyEscape
	case "tab":
		return tea.KeyTab
	case "up":
		return tea.KeyUp
	case "down":
		return tea.KeyDown
	case "left":
		return tea.KeyLeft
	case "right":
		return tea.KeyRight
	}
	return 0
}
