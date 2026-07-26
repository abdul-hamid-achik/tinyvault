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
	v := newScratchSession(t)
	for _, sz := range [][2]int{{120, 40}, {100, 30}, {90, 24}, {160, 50}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(mustLoadStatus(t, v)))
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
	v := newScratchSession(t)
	for _, sz := range [][2]int{{70, 20}, {80, 24}, {50, 15}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(mustLoadStatus(t, v)))
		secs, _ := loadSecrets(v, m.viewProject)
		m = update(t, m, secretsLoadedMsg{project: m.viewProject, refs: secs})
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

func TestGridExactAfterReveal(t *testing.T) {
	v := newScratchSession(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3"))
	m = update(t, m, keyPress("down"))
	ref, _ := m.currentSecret()
	m = update(t, m, revealedMsg{project: ref.Project, key: ref.Key, value: "sk_live_VERYLONGVALUEHERE_padding"})
	assertExactGrid(t, m.View().Content, 120, 40)
}

func TestGridExactInFilterAndStatusLine(t *testing.T) {
	v := newScratchSession(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("/"))
	m = update(t, m, keyPress("D"))
	assertExactGrid(t, m.View().Content, 120, 40)
}

// TestGridExactHelpOverlay guards the help overlay (modeHelp) at many
// sizes, including the small ones where the glamour box can't fully fit —
// the overlay must still produce an exact w×h grid (clampGrid backstop).
func TestGridExactHelpOverlay(t *testing.T) {
	v := newScratchSession(t)
	for _, sz := range [][2]int{{120, 40}, {100, 30}, {90, 24}, {160, 50}, {40, 10}, {50, 12}, {80, 14}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(mustLoadStatus(t, v)))
		m = update(t, m, keyPress("?"))
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

// TestGridExactEditOverlay guards the --rw edit modal (modeNewKey /
// modeSetValue) at several sizes, including with a value far longer than the
// modal box — the sized textinput must scroll within its field rather than
// overflow the frame.
func TestGridExactEditOverlay(t *testing.T) {
	v := newScratchSession(t)
	longVal := "postgres://user:pw@some-very-long-host.example.com:5432/a_long_database_name?sslmode=require"
	for _, sz := range [][2]int{{120, 40}, {100, 30}, {90, 24}, {160, 50}, {40, 10}} {
		m := New(v, Options{ReadWrite: true})
		m.anim = false
		m.rw = true
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(mustLoadStatus(t, v)))
		// modeNewKey: the key-name field (empty → placeholder must fit).
		m = update(t, m, keyPress("n"))
		if m.mode != modeNewKey {
			t.Fatalf("expected modeNewKey at %dx%d", sz[0], sz[1])
		}
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
		// modeSetValue with a long value: must stay within the frame.
		m = update(t, m, keyPress("K"))
		m = update(t, m, keyPress("enter"))
		for _, r := range longVal {
			m = update(t, m, keyPress(string(r)))
		}
		if m.mode != modeSetValue {
			t.Fatalf("expected modeSetValue at %dx%d", sz[0], sz[1])
		}
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

// TestGridExactUnlockOverlay guards the unlock modal (modeUnlock) — only
// reachable on a locked vault — at several sizes.
func TestGridExactUnlockOverlay(t *testing.T) {
	v := newScratchSession(t)
	v.Lock()
	for _, sz := range [][2]int{{120, 40}, {90, 24}, {40, 10}, {50, 12}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(mustLoadStatus(t, v)))
		m = update(t, m, keyPress("u"))
		if m.mode != modeUnlock {
			t.Fatalf("expected modeUnlock at %dx%d", sz[0], sz[1])
		}
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

// TestGridExactWithServiceRows covers the agent/service rows in the status
// pane. They are appended after the env-group rows, so they are the most likely
// thing to push the pane past its allotted height and corrupt Bubble Tea's
// cell-diff renderer.
func TestGridExactWithServiceRows(t *testing.T) {
	v := newScratchSession(t)
	// The narrow/short sizes matter most: that is where extra rows overflow.
	for _, sz := range [][2]int{{120, 40}, {90, 24}, {80, 20}, {60, 14}, {40, 10}} {
		for _, svc := range []serviceData{
			{probed: true}, // nothing installed
			{probed: true, agentRunning: true, agentPID: 4242}, // agent only
			{probed: true, agentRunning: true, agentPID: 4242, agentIdleRemaining: 900},
			{probed: true, serviceKind: "launchd", serviceRegistered: true},  // service only
			{probed: true, serviceKind: "systemd", serviceRegistered: false}, // installed, not registered
			{
				probed: true, agentRunning: true, agentPID: 4242, agentIdleRemaining: 3600,
				serviceKind: "launchd", serviceRegistered: true,
			}, // both, the widest case
		} {
			m := New(v, Options{})
			m.anim = false
			m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
			m = update(t, m, statusLoadedMsg(mustLoadStatus(t, v)))
			m = update(t, m, serviceLoadedMsg(svc))
			assertExactGrid(t, m.View().Content, sz[0], sz[1])
		}
	}
}

// TestServiceRowsAreOmittedBeforeProbe keeps the pane quiet until the async
// probe returns, instead of briefly claiming there is no agent.
func TestServiceRowsAreOmittedBeforeProbe(t *testing.T) {
	v := newScratchSession(t)
	m := New(v, Options{})
	if rows := m.serviceRows(80); rows != nil {
		t.Errorf("expected no rows before the probe, got %v", rows)
	}
}

// TestServiceRowsOmitAbsences documents the choice not to render "no"/"none":
// the common case is no agent and no service, and padding the pane with
// absences would push out what the studio is actually for.
func TestServiceRowsOmitAbsences(t *testing.T) {
	v := newScratchSession(t)
	m := New(v, Options{})
	m.svc = serviceData{probed: true}
	if rows := m.serviceRows(80); len(rows) != 0 {
		t.Errorf("a probed-but-empty state should render nothing, got %v", rows)
	}
}

// TestServiceRowsContent pins what the rows actually say, so the pane cannot
// silently stop reporting a running agent or an unregistered service.
func TestServiceRowsContent(t *testing.T) {
	v := newScratchSession(t)
	m := New(v, Options{})

	m.svc = serviceData{probed: true, agentRunning: true, agentPID: 4242, agentIdleRemaining: 900}
	rows := strings.Join(m.serviceRows(120), "\n")
	for _, want := range []string{"agent", "pid 4242", "locks in 15m"} {
		if !strings.Contains(rows, want) {
			t.Errorf("agent row missing %q, got %q", want, rows)
		}
	}

	m.svc = serviceData{probed: true, serviceKind: "launchd", serviceRegistered: true}
	rows = strings.Join(m.serviceRows(120), "\n")
	if !strings.Contains(rows, "launchd") || !strings.Contains(rows, "registered") {
		t.Errorf("service row should name the manager and its state, got %q", rows)
	}

	// Installed but not registered must be visibly different: the definition is
	// on disk yet nothing will start it.
	m.svc = serviceData{probed: true, serviceKind: "systemd", serviceRegistered: false}
	rows = strings.Join(m.serviceRows(120), "\n")
	if !strings.Contains(rows, "not registered") {
		t.Errorf("an unregistered service must say so, got %q", rows)
	}
}
