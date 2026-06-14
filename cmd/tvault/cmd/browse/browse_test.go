package browse

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// newScratchVault creates a temp vault populated with two projects and a
// handful of secrets + audit entries. It is the shared fixture for the
// data and model tests.
func newScratchVault(t *testing.T) *vault.Vault {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Create(dir, "test-pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

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
	return v
}

// newReadyModel builds a model the way the program would after the first
// window-size + data-load round trip, ready for synthetic key events.
func newReadyModel(t *testing.T, v *vault.Vault, opts Options) Model {
	t.Helper()
	m := New(v, opts)
	m.anim = false // deterministic tests: no frame loop
	m = update(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = update(t, m, statusLoadedMsg(loadStatus(v)))
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
