package studio

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"
)

// assertExactGrid checks the rendered screen is exactly w×h cells. Bubble
// Tea's cell-diff renderer corrupts the display when frames are not the
// full terminal size, so this is a core invariant for every layout.
func assertExactGrid(t *testing.T, content string, w, h int) {
	t.Helper()
	lines := strings.Split(content, "\n")
	if len(lines) != h {
		t.Errorf("rendered %d rows, want %d", len(lines), h)
	}
	for i, ln := range lines {
		if got := lipgloss.Width(ln); got != w {
			t.Errorf("row %d width = %d, want %d: %q", i, got, w, stripANSIForTest(ln))
		}
	}
}

func stripANSIForTest(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case inEsc:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestMultiPaneGridExact(t *testing.T) {
	v := newScratchVault(t)
	for _, sz := range [][2]int{{120, 40}, {100, 30}, {90, 24}, {160, 50}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(loadStatus(v)))
		projects, _ := loadProjects(v)
		m = update(t, m, projectsLoadedMsg{projects: projects})
		secs, _ := loadSecrets(v, m.viewProject)
		m = update(t, m, secretsLoadedMsg{project: m.viewProject, refs: secs})
		audit, _ := loadAudit(v, 100)
		m = update(t, m, auditLoadedMsg{entries: audit})
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

func TestSinglePaneGridExact(t *testing.T) {
	v := newScratchVault(t)
	for _, sz := range [][2]int{{70, 20}, {80, 24}, {50, 15}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(loadStatus(v)))
		secs, _ := loadSecrets(v, m.viewProject)
		m = update(t, m, secretsLoadedMsg{project: m.viewProject, refs: secs})
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

func TestGridExactAfterReveal(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	m = update(t, m, keyPress("down"))
	ref, _ := m.currentSecret()
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "sk_live_VERYLONGVALUEHERE_padding"})
	assertExactGrid(t, m.View().Content, 120, 40)
}

func TestGridExactInFilterAndStatusLine(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("/"))
	m = update(t, m, keyPress("D"))
	assertExactGrid(t, m.View().Content, 120, 40)
}

// TestGridExactHelpOverlay guards the help overlay (modeHelp) at many
// sizes, including the small ones where the glamour box can't fully fit —
// the overlay must still produce an exact w×h grid (clampGrid backstop).
func TestGridExactHelpOverlay(t *testing.T) {
	v := newScratchVault(t)
	for _, sz := range [][2]int{{120, 40}, {100, 30}, {90, 24}, {160, 50}, {40, 10}, {50, 12}, {80, 14}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(loadStatus(v)))
		m = update(t, m, keyPress("?"))
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

// TestGridExactUnlockOverlay guards the unlock modal (modeUnlock) — only
// reachable on a locked vault — at several sizes.
func TestGridExactUnlockOverlay(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	for _, sz := range [][2]int{{120, 40}, {90, 24}, {40, 10}, {50, 12}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(loadStatus(v)))
		m = update(t, m, keyPress("u"))
		if m.mode != modeUnlock {
			t.Fatalf("expected modeUnlock at %dx%d", sz[0], sz[1])
		}
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}
