package browse

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestCopyFlow(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))

	_, cmd := m.Update(keyPress("c"))
	if cmd == nil {
		t.Fatal("c should issue a copy command on an unlocked vault")
	}
	msg := cmd()
	cm, ok := msg.(copiedMsg)
	if !ok {
		t.Fatalf("copy cmd produced %T, want copiedMsg", msg)
	}
	next, clip := m.Update(cm)
	got := next.(Model)
	if !strings.Contains(got.statusLine, "copied") {
		t.Errorf("statusLine = %q, want a 'copied' confirmation", got.statusLine)
	}
	if clip == nil {
		t.Error("copiedMsg should return a SetClipboard command")
	}
}

func TestCopyAlreadyRevealedUsesCache(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	ref, _ := m.currentSecret()
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "cached"})
	next, clip := m.Update(keyPress("c"))
	got := next.(Model)
	if clip == nil || !strings.Contains(got.statusLine, "copied") {
		t.Error("copy of an already-revealed secret should set clipboard directly")
	}
}

func TestRevealAll(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	next, cmd := m.Update(keyPress("R"))
	got := next.(Model)
	if !got.revealAll {
		t.Error("R should set revealAll")
	}
	if cmd == nil {
		t.Error("R should issue reveal commands")
	}
}

func TestLockClearsReveals(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	ref, _ := m.currentSecret()
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "x"})
	if len(m.revealed) == 0 {
		t.Fatal("setup: expected a revealed value")
	}
	m = update(t, m, keyPress("L"))
	if v.IsUnlocked() {
		t.Error("L should lock the vault")
	}
	if len(m.revealed) != 0 {
		t.Error("locking should wipe revealed values")
	}
}

func TestProjectEnterLoadsSecrets(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("2")) // projects
	// move to the "api" project (sorted: api, default, webapp).
	m = update(t, m, keyPress("k")) // up — clamps at top (api)
	m.projCursor = 0                // ensure cursor on api
	next, cmd := m.Update(keyPress("enter"))
	got := next.(Model)
	if got.viewProject != "api" {
		t.Errorf("enter on api set viewProject = %q, want api", got.viewProject)
	}
	if got.active != paneSecrets {
		t.Error("enter should focus the secrets pane")
	}
	if cmd == nil {
		t.Error("enter should issue a secrets load command")
	}
}

func TestProjectNavigatePreviews(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("2")) // projects, cursor on webapp (current)
	start := m.viewProject
	next, cmd := m.Update(keyPress("up"))
	got := next.(Model)
	if got.viewProject == start {
		t.Skip("cursor already at an edge; preview unchanged")
	}
	if cmd == nil {
		t.Error("moving the project cursor should preview that project's secrets")
	}
}

func TestAuditNavigation(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("4")) // audit
	before := m.auditOffset
	m = update(t, m, keyPress("down"))
	if m.auditOffset < before {
		t.Error("down should not decrease the audit offset")
	}
}

func TestReloadAndRedraw(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Mod: tea.ModCtrl})
	if cmd == nil {
		t.Error("ctrl+r should issue reload commands")
	}
	_, cmd = m.Update(tea.KeyPressMsg{Code: 'l', Mod: tea.ModCtrl})
	if cmd == nil {
		t.Error("ctrl+l should issue a redraw command")
	}
}

func TestHelpOverlayRenders(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("?"))
	out := m.View().Content
	if !strings.Contains(out, "Help") {
		t.Errorf("help overlay missing title:\n%s", out)
	}
	// the glamour-rendered body should mention a core concept.
	if !strings.Contains(out, "Panes") && !strings.Contains(out, "Navigation") {
		t.Errorf("help overlay missing body content:\n%s", out)
	}
}

func TestUnlockOverlayRenders(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("u"))
	out := m.View().Content
	if !strings.Contains(out, "Unlock vault") {
		t.Errorf("unlock overlay missing title:\n%s", out)
	}
}

func TestResizeRelayout(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("?")) // help mode — relayout must re-render help
	m = update(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	if m.width != 100 || m.height != 30 {
		t.Errorf("resize not applied: %dx%d", m.width, m.height)
	}
	// still renders without panic at the new size.
	_ = m.View().Content
}

func TestRevealFlashUnderlinesValue(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m.anim = true
	m = update(t, m, keyPress("3"))
	ref, _ := m.currentSecret()
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "FLASHVAL"})
	out := m.View().Content
	if !strings.Contains(out, "FLASHVAL") {
		t.Errorf("revealed value should appear in the screen:\n%s", out)
	}
}

func TestLockedSinglePaneHint(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	m := New(v, Options{SinglePane: true})
	m.anim = false
	m = update(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m = update(t, m, statusLoadedMsg(loadStatus(v)))
	m = update(t, m, keyPress("3"))
	out := m.View().Content
	if !strings.Contains(out, "locked") {
		t.Errorf("locked secrets pane should hint about unlocking:\n%s", out)
	}
}

func TestMouseWheelMovesCursor(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3")) // secrets
	if m.secCursor != 0 {
		t.Fatalf("setup secCursor=%d", m.secCursor)
	}
	m = update(t, m, tea.MouseWheelMsg{Button: tea.MouseWheelDown})
	if m.secCursor != 1 {
		t.Errorf("wheel down: secCursor=%d, want 1", m.secCursor)
	}
	m = update(t, m, tea.MouseWheelMsg{Button: tea.MouseWheelUp})
	if m.secCursor != 0 {
		t.Errorf("wheel up: secCursor=%d, want 0", m.secCursor)
	}
}

func TestPaneChangeWipesReveals(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3")) // secrets
	ref, _ := m.currentSecret()
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "secret"})
	if len(m.revealed) == 0 {
		t.Fatal("setup: expected a revealed value")
	}
	// Switching panes must wipe revealed values (documented security model).
	m = update(t, m, keyPress("1")) // -> status
	if len(m.revealed) != 0 {
		t.Errorf("pane change must wipe revealed values, got %d", len(m.revealed))
	}
}

func TestLateRevealAfterEscDropped(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	ref, _ := m.currentSecret()
	// Simulate pressing r (capture the in-flight epoch), then esc wipes
	// and bumps the epoch, THEN the async revealedMsg arrives stale.
	epoch := m.revealEpoch
	m = update(t, m, keyPress("esc")) // wipe + bump epoch
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "LEAK", epoch: epoch})
	if len(m.revealed) != 0 {
		t.Errorf("stale reveal after esc must be dropped, got %v", m.revealed)
	}
	if strings.Contains(m.View().Content, "LEAK") {
		t.Error("resurrected plaintext leaked into the rendered screen")
	}
}

func TestLateRevealWrongProjectDropped(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	// A reveal tagged for a different project than the one in view is dropped.
	m = update(t, m, revealedMsg{project: "some-other-project", key: "X", value: "LEAK", epoch: m.revealEpoch})
	if len(m.revealed) != 0 {
		t.Errorf("reveal for a non-viewed project must be dropped, got %v", m.revealed)
	}
}

func TestReloadWipesReveals(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	ref, _ := m.currentSecret()
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "x", epoch: m.revealEpoch})
	if len(m.revealed) == 0 {
		t.Fatal("setup: expected a revealed value")
	}
	m = update(t, m, tea.KeyPressMsg{Code: 'r', Mod: tea.ModCtrl}) // ctrl+r reload
	if len(m.revealed) != 0 {
		t.Error("reload should wipe revealed values")
	}
}
