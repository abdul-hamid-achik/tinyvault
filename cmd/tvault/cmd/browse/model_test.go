package browse

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func TestQuitKey(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	next, cmd := m.Update(keyPress("q"))
	got := next.(Model)
	if !got.quitting {
		t.Error("q should set quitting")
	}
	if cmd == nil {
		t.Fatal("q should return a command (tea.Quit)")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("q command produced %T, want tea.QuitMsg", cmd())
	}
}

func TestPaneSwitching(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})

	for _, tc := range []struct {
		key  string
		want paneID
	}{
		{"1", paneStatus},
		{"2", paneProjects},
		{"3", paneSecrets},
		{"4", paneAudit},
	} {
		m = update(t, m, keyPress(tc.key))
		if m.active != tc.want {
			t.Errorf("after %q active = %d, want %d", tc.key, m.active, tc.want)
		}
	}

	// tab cycles forward from audit -> status.
	m = update(t, m, keyPress("tab"))
	if m.active != paneStatus {
		t.Errorf("tab from audit -> %d, want paneStatus", m.active)
	}
}

func TestNavigateSecrets(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3")) // focus secrets
	if m.secCursor != 0 {
		t.Fatalf("initial secCursor = %d, want 0", m.secCursor)
	}
	m = update(t, m, keyPress("down"))
	if m.secCursor != 1 {
		t.Errorf("after down secCursor = %d, want 1", m.secCursor)
	}
	// Clamp at the bottom.
	for i := 0; i < 10; i++ {
		m = update(t, m, keyPress("down"))
	}
	if m.secCursor != len(m.secrets)-1 {
		t.Errorf("secCursor = %d, want clamped to %d", m.secCursor, len(m.secrets)-1)
	}
}

func TestRevealAndHide(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3")) // secrets

	ref, ok := m.currentSecret()
	if !ok {
		t.Fatal("expected a current secret")
	}
	// Press r -> issues reveal cmd; run it and feed the result back.
	_, cmd := m.Update(keyPress("r"))
	if cmd == nil {
		t.Fatal("r should produce a reveal command on an unlocked vault")
	}
	msg := cmd()
	rm, ok := msg.(revealedMsg)
	if !ok {
		t.Fatalf("reveal cmd produced %T, want revealedMsg", msg)
	}
	m = update(t, m, rm)
	if _, shown := m.revealed[ref.Project+"/"+ref.Key]; !shown {
		t.Error("value should be in the reveal map after revealedMsg")
	}

	// esc wipes revealed values.
	m = update(t, m, keyPress("esc"))
	if len(m.revealed) != 0 {
		t.Errorf("esc should clear reveal map, got %d entries", len(m.revealed))
	}
}

func TestRevealBlockedWhenLocked(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	_, cmd := m.Update(keyPress("r"))
	if cmd != nil {
		t.Error("r on a locked vault should not issue a reveal command")
	}
	next := update(t, m, keyPress("r"))
	if !strings.Contains(next.statusLine, "locked") {
		t.Errorf("statusLine = %q, want a 'locked' hint", next.statusLine)
	}
}

func TestWipeRevealedOnQuit(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	ref, _ := m.currentSecret()
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "secret"})
	if len(m.revealed) == 0 {
		t.Fatal("setup: expected a revealed value")
	}
	m = update(t, m, keyPress("q"))
	if len(m.revealed) != 0 {
		t.Error("quit must wipe revealed values from memory")
	}
}

func TestFilterSecrets(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	if len(m.secrets) != 3 {
		t.Fatalf("setup: %d secrets, want 3", len(m.secrets))
	}
	// Enter filter mode and type "DB".
	m = update(t, m, keyPress("/"))
	if m.mode != modeFilter {
		t.Fatalf("/ should enter filter mode, got %d", m.mode)
	}
	m = update(t, m, keyPress("D"))
	m = update(t, m, keyPress("B"))
	if len(m.secrets) != 1 || m.secrets[0].Key != "DB_URL" {
		t.Errorf("filter DB -> %v, want [DB_URL]", secretKeys(m.secrets))
	}
	// esc clears the filter.
	m = update(t, m, keyPress("esc"))
	if m.mode != modeNormal {
		t.Error("esc should leave filter mode")
	}
	if len(m.secrets) != 3 {
		t.Errorf("esc should clear filter, got %d secrets", len(m.secrets))
	}
}

func TestUnlockFlow(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	m := newReadyModel(t, v, Options{})
	if m.status.unlocked {
		t.Fatal("setup: vault should be locked")
	}
	// u opens the unlock modal.
	m = update(t, m, keyPress("u"))
	if m.mode != modeUnlock {
		t.Fatalf("u should enter unlock mode, got %d", m.mode)
	}
	// type the passphrase then enter.
	for _, r := range "test-pass" {
		m = update(t, m, keyPress(string(r)))
	}
	next, cmd := m.Update(keyPress("enter"))
	m = next.(Model)
	if m.mode != modeNormal {
		t.Error("enter should leave unlock mode")
	}
	if !v.IsUnlocked() {
		t.Error("correct passphrase should unlock the vault")
	}
	if cmd == nil {
		t.Error("successful unlock should refresh status")
	}
}

func TestUnlockWrongPassphraseShakes(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("u"))
	for _, r := range "wrong" {
		m = update(t, m, keyPress(string(r)))
	}
	m = update(t, m, keyPress("enter"))
	if v.IsUnlocked() {
		t.Error("wrong passphrase must not unlock")
	}
	if !strings.Contains(m.statusLine, "unlock failed") {
		t.Errorf("statusLine = %q, want unlock failure", m.statusLine)
	}
}

func TestHelpToggle(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("?"))
	if m.mode != modeHelp {
		t.Fatal("? should open help")
	}
	m = update(t, m, keyPress("?"))
	if m.mode != modeNormal {
		t.Error("? should close help")
	}
}

// TestViewRendersCoherentScreen is the headless render smoke test: feed a
// fully loaded model and assert the rendered screen has the expected
// landmarks. This catches layout/format regressions without a PTY.
func TestViewRendersCoherentScreen(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	out := m.View().Content

	for _, want := range []string{"tvault", "unlocked", "Status", "Projects", "Secrets", "Audit", "STRIPE_KEY", "webapp"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered screen missing %q\n---\n%s", want, out)
		}
	}
	// Values must be masked, never shown, before reveal.
	if strings.Contains(out, "sk_live_abc123") {
		t.Error("unrevealed secret value leaked into the rendered screen")
	}
}

func TestViewSinglePaneNarrow(t *testing.T) {
	v := newScratchVault(t)
	m := New(v, Options{})
	m.anim = false
	m = update(t, m, tea.WindowSizeMsg{Width: 70, Height: 20})
	m = update(t, m, statusLoadedMsg(loadStatus(v)))
	out := m.View().Content
	// Single-pane mode shows a tab strip with numbered panes.
	if !strings.Contains(out, "3 Secrets") {
		t.Errorf("single-pane view missing tab strip\n---\n%s", out)
	}
}

func TestViewTooSmall(t *testing.T) {
	v := newScratchVault(t)
	m := New(v, Options{})
	m.anim = false
	m = update(t, m, tea.WindowSizeMsg{Width: 20, Height: 5})
	out := m.View().Content
	if !strings.Contains(out, "too small") {
		t.Errorf("tiny terminal should show a 'too small' message, got:\n%s", out)
	}
}

func secretKeys(refs []vault.SecretRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Key
	}
	return out
}
