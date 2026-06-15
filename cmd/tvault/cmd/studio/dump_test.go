package studio

import (
	"os"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestDumpScreen is a manual inspection helper. Run with:
//
//	TVAULT_TUI_DUMP=1 go test ./cmd/tvault/cmd/tui/ -run TestDumpScreen -v
//
// It prints the rendered screen (with ANSI) so a human/agent can eyeball
// the layout. Skipped unless TVAULT_TUI_DUMP is set.
func TestDumpScreen(t *testing.T) {
	if os.Getenv("TVAULT_TUI_DUMP") == "" {
		t.Skip("set TVAULT_TUI_DUMP=1 to dump the rendered screen")
	}
	v := newScratchVault(t)
	w, h := 120, 40
	if cs := os.Getenv("TVAULT_TUI_COLS"); cs != "" {
		_, _ = sscan(cs, &w)
	}
	if rs := os.Getenv("TVAULT_TUI_ROWS"); rs != "" {
		_, _ = sscan(rs, &h)
	}
	m := New(v, Options{})
	m.anim = false
	m = update(t, m, tea.WindowSizeMsg{Width: w, Height: h})
	m = update(t, m, statusLoadedMsg(loadStatus(v)))
	projects, _ := loadProjects(v)
	m = update(t, m, projectsLoadedMsg{projects: projects})
	secs, _ := loadSecrets(v, m.viewProject)
	m = update(t, m, secretsLoadedMsg{project: m.viewProject, refs: secs})
	audit, _ := loadAudit(v, 100)
	m = update(t, m, auditLoadedMsg{entries: audit})

	os.Stdout.WriteString("\n" + m.View().Content + "\n")
}

func sscan(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	if n > 0 {
		*out = n
	}
	return 1, nil
}
