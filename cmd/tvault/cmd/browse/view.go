package browse

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"
)

// maskDots is the placeholder shown for an un-revealed secret value.
const maskDots = "••••••••"

func (m Model) View() tea.View {
	v := tea.NewView("")
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.BackgroundColor = m.styles.pal.bg
	v.ForegroundColor = m.styles.pal.fg
	v.WindowTitle = m.windowTitle()

	if m.quitting {
		v.SetContent("")
		return v
	}
	if !m.ready {
		v.SetContent(m.styles.muted.Render("loading…"))
		return v
	}
	if m.width < minTermW || m.height < minTermH {
		v.SetContent(m.styles.warn.Render(
			fmt.Sprintf("terminal too small (%dx%d) — need at least %dx%d",
				m.width, m.height, minTermW, minTermH)))
		return v
	}

	header := m.renderHeader()
	footer := m.renderFooter()
	bodyH := m.height - 3 // header(1) + status line(1) + help(1)
	if bodyH < 3 {
		bodyH = 3
	}

	var middle string
	switch m.mode {
	case modeHelp:
		middle = m.renderHelpOverlay(bodyH)
	case modeUnlock:
		middle = m.renderUnlockOverlay(bodyH)
	case modeNewKey, modeSetValue:
		middle = m.renderEditOverlay(bodyH)
	case modeConfirmDel:
		middle = m.renderConfirmOverlay(bodyH)
	default:
		middle = m.renderBody(m.width, bodyH)
	}

	v.SetContent(lipgloss.JoinVertical(lipgloss.Left, header, middle, footer))
	return v
}

func (m Model) windowTitle() string {
	lock := "locked"
	if m.status.unlocked {
		lock = "unlocked"
	}
	proj := m.viewProject
	if proj == "" {
		proj = "—"
	}
	return fmt.Sprintf("tvault — %s · %s · %d secrets", proj, lock, len(m.allSecrets))
}

// ---- header ----

func (m Model) renderHeader() string {
	sep := m.styles.headerSep.Render("  •  ")
	parts := []string{m.styles.wordmark.Render("tvault")}

	// lock state
	if m.status.unlocked {
		parts = append(parts, m.styles.good.Render("● unlocked"))
	} else {
		dot := "●"
		lockStyle := m.styles.warn
		if m.anim {
			a := pulseAlpha(m.now.Sub(m.start), pulsePeriod, 0.35, 1.0)
			lockStyle = lipgloss.NewStyle().Foreground(fadeColor(m.styles.pal.warn, a))
		}
		parts = append(parts, lockStyle.Render(dot+" locked"))
	}
	if m.rw {
		parts = append(parts, m.styles.revealed.Render("rw")) // writes enabled
	}

	proj := m.viewProject
	if proj == "" {
		proj = "—"
	}
	parts = append(parts,
		m.styles.accent.Render(proj),
		m.styles.headerMeta.Render(fmt.Sprintf("%d secrets", m.secretCount())),
		m.styles.headerMeta.Render(fmt.Sprintf("%d projects", len(m.projects))),
	)

	line := strings.Join(parts, sep)
	return truncate(line, m.width)
}

// ---- footer ----

func (m Model) renderFooter() string {
	// status/filter line
	var statusRow string
	switch m.mode {
	case modeFilter:
		label := m.styles.filterLabel.Render("filter")
		statusRow = label + " " + m.filter.View()
	default:
		switch {
		case m.loading:
			statusRow = m.styles.accent.Render(m.spin.View()) + m.styles.muted.Render(" loading…")
		case m.statusLine != "":
			statusRow = m.styles.accent.Render(m.statusLine)
		case m.lastErr != nil:
			statusRow = m.styles.bad.Render(m.lastErr.Error())
		default:
			statusRow = m.styles.muted.Render(m.activeHint())
		}
	}
	statusRow = truncate(statusRow, m.width)

	hints := m.help.ShortHelpView(m.keys.ShortHelp())
	hints = truncate(hints, m.width)

	return lipgloss.JoinVertical(lipgloss.Left, statusRow, hints)
}

// activeHint gives a context line for the focused pane.
func (m Model) activeHint() string {
	switch m.active {
	case paneStatus:
		return "status — vault health at a glance"
	case paneProjects:
		return "projects — ↑↓ to preview, ⏎ to open"
	case paneSecrets:
		if !m.status.unlocked {
			return "secrets — locked; press u to unlock, then r to reveal"
		}
		if m.rw {
			return "secrets — r reveal · c copy · n new · e edit · d delete · / filter"
		}
		return "secrets — r reveal · R reveal all · c copy · / filter"
	case paneAudit:
		return "audit — most recent activity (newest first)"
	default:
		return ""
	}
}

// ---- body / panes ----

func (m Model) renderBody(w, h int) string {
	if m.opts.SinglePane || w < multiPaneMinW || h < multiPaneMinH {
		return m.renderSinglePane(w, h)
	}
	return m.renderMultiPane(w, h)
}

func (m Model) renderSinglePane(w, h int) string {
	tabs := m.renderTabStrip(w)
	box := m.renderPane(m.active, w, h-1)
	return lipgloss.JoinVertical(lipgloss.Left, tabs, box)
}

func (m Model) renderTabStrip(w int) string {
	var tabs []string
	for p := paneStatus; p < paneCount; p++ {
		label := fmt.Sprintf("%d %s", int(p)+1, p.title())
		if p == m.active {
			tabs = append(tabs, m.styles.tabHot.Render(label))
		} else {
			tabs = append(tabs, m.styles.tab.Render(label))
		}
	}
	return truncate(strings.Join(tabs, " "), w)
}

func (m Model) renderMultiPane(w, h int) string {
	leftW := clampInt(w*28/100, 22, 34)
	rightW := w - leftW - 1
	if rightW < 24 {
		rightW = w - leftW
		leftW = 0
	}

	statusH := clampInt(h/2, 6, 9)
	projectsH := h - statusH
	if projectsH < 3 {
		projectsH = 3
		statusH = h - projectsH
	}

	auditH := clampInt(h/3, 5, h-6)
	secretsH := h - auditH
	if secretsH < 4 {
		secretsH = 4
		auditH = h - secretsH
	}

	left := lipgloss.JoinVertical(lipgloss.Left,
		m.renderPane(paneProjects, leftW, projectsH),
		m.renderPane(paneStatus, leftW, statusH),
	)
	right := lipgloss.JoinVertical(lipgloss.Left,
		m.renderPane(paneSecrets, rightW, secretsH),
		m.renderPane(paneAudit, rightW, auditH),
	)

	if leftW == 0 {
		return right
	}
	gutter := strings.TrimRight(strings.Repeat(" \n", h), "\n")
	return lipgloss.JoinHorizontal(lipgloss.Top, left, gutter, right)
}

// renderPane draws one bordered, titled pane sized to exactly boxW×boxH.
func (m Model) renderPane(id paneID, boxW, boxH int) string {
	innerW := boxW - 2
	innerH := boxH - 2
	if innerW < 1 {
		innerW = 1
	}
	if innerH < 1 {
		innerH = 1
	}
	bodyH := innerH - 1 // title takes one row
	if bodyH < 1 {
		bodyH = 1
	}

	focused := m.active == id && m.mode == modeNormal
	titleStyle := m.styles.title
	frame := m.styles.pane
	if focused {
		titleStyle = m.styles.titleHot
		frame = m.styles.paneActive
	}

	title := titleStyle.Render(truncate(paneTitleText(id, m), innerW))

	var lines []string
	switch id {
	case paneStatus:
		lines = m.statusBody(innerW, bodyH)
	case paneProjects:
		lines = m.projectsBody(innerW, bodyH, focused)
	case paneSecrets:
		lines = m.secretsBody(innerW, bodyH, focused)
	case paneAudit:
		lines = m.auditBody(innerW, bodyH)
	default:
		// paneCount sentinel: no body
	}
	lines = fitLines(lines, innerW, bodyH)

	content := title + "\n" + strings.Join(lines, "\n")
	// In lipgloss v2, Width/Height set the TOTAL box size (border
	// inclusive); the content area is therefore boxW-2 × boxH-2, which is
	// exactly innerW × innerH. Setting the full box size keeps the frame
	// the size the layout asked for — a mismatch corrupts Bubble Tea's
	// cell-diff renderer.
	return frame.Width(boxW).Height(boxH).Render(content)
}

func paneTitleText(id paneID, m Model) string {
	base := fmt.Sprintf("%d %s", int(id)+1, id.title())
	switch id {
	case paneProjects:
		return fmt.Sprintf("%s (%d)", base, len(m.projects))
	case paneSecrets:
		if m.filter.Value() != "" {
			return fmt.Sprintf("%s (%d/%d)", base, len(m.secrets), len(m.allSecrets))
		}
		return fmt.Sprintf("%s (%d)", base, len(m.allSecrets))
	case paneAudit:
		return fmt.Sprintf("%s (%d)", base, len(m.audit))
	default:
		return base
	}
}

// fitLines truncates/pads a slice to exactly h lines, each ≤ w cells.
func fitLines(lines []string, w, h int) []string {
	out := make([]string, 0, h)
	for i := 0; i < h; i++ {
		if i < len(lines) {
			out = append(out, truncate(lines[i], w))
		} else {
			out = append(out, "")
		}
	}
	return out
}

// ---- pane bodies ----

func (m Model) statusBody(w, _ int) []string {
	lock := m.styles.good.Render("● unlocked")
	if !m.status.unlocked {
		lock = m.styles.warn.Render("● locked")
	}
	proj := m.viewProject
	if proj == "" {
		proj = "—"
	}
	vid := m.status.vaultID
	if len(vid) > 8 {
		vid = vid[:8]
	}
	rows := []string{
		lock,
		kv(m.styles, "project", proj, w),
		kv(m.styles, "secrets", fmt.Sprintf("%d", m.secretCount()), w),
		kv(m.styles, "projects", fmt.Sprintf("%d", len(m.projects)), w),
		kv(m.styles, "updated", humanizeSince(m.lastWrite()), w),
		kv(m.styles, "vault", vid, w),
	}
	return rows
}

func kv(s themeStyles, k, val string, w int) string {
	label := s.muted.Render(padRight(k, 9))
	return truncate(label+s.row.Render(val), w)
}

func (m Model) projectsBody(w, h int, focused bool) []string {
	if len(m.projects) == 0 {
		return []string{m.styles.muted.Render("no projects")}
	}
	start, end := scrollWindow(len(m.projects), h, m.projCursor)
	nameW := w - 2 - 4 // marker(2) + count budget(up to 4)
	if nameW < 1 {
		nameW = 1
	}
	out := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		p := m.projects[i]
		isCurrent := p.Name == m.status.currentProject
		markerTxt := "  "
		if isCurrent {
			markerTxt = "▸ "
		}
		name := padRight(truncate(p.Name, nameW), nameW)
		countTxt := fmt.Sprintf("%d", p.SecretCount)

		if i == m.projCursor {
			// Selected row: one uniform highlight over plain text.
			plain := markerTxt + name + " " + countTxt
			out = append(out, truncate(selectStyle(m.styles, focused).Render(truncate(plain, w)), w))
			continue
		}
		marker := markerTxt
		if isCurrent {
			marker = m.styles.accent.Render(markerTxt)
		}
		line := marker + m.styles.row.Render(name) + " " + m.styles.muted.Render(countTxt)
		out = append(out, truncate(line, w))
	}
	return out
}

func (m Model) secretsBody(w, h int, focused bool) []string {
	if !m.status.unlocked && len(m.secrets) == 0 {
		return []string{m.styles.muted.Render("locked — press u")}
	}
	if len(m.secrets) == 0 {
		if m.filter.Value() != "" {
			return []string{m.styles.muted.Render("no keys match filter")}
		}
		return []string{m.styles.muted.Render("no secrets in this project")}
	}
	secs := m.secrets // already sorted by key in applyFilter
	start, end := scrollWindow(len(secs), h, m.secCursor)
	keyW := clampInt(w*45/100, 8, 40)
	valW := w - keyW - 1
	if valW < 4 {
		valW = 4
	}
	out := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		ref := secs[i]
		key := truncate(ref.Key, keyW)
		val, shown := m.revealed[ref.Project+"/"+ref.Key]
		var valCell string
		if shown {
			vs := m.styles.revealed
			if m.anim && ref.Key == m.flashKey && m.now.Before(m.flashUntil) {
				vs = vs.Underline(true)
			}
			valCell = vs.Render(truncate(val, valW))
		} else {
			valCell = m.styles.masked.Render(maskDots)
		}
		plain := padRight(key, keyW) + " " + plainValue(val, shown, valW)
		if i == m.secCursor {
			out = append(out, truncate(selectStyle(m.styles, focused).Render(truncate(plain, w)), w))
			continue
		}
		ks := m.styles.row.Render(padRight(key, keyW))
		out = append(out, truncate(ks+" "+valCell, w))
	}
	return out
}

func (m Model) auditBody(w, h int) []string {
	if len(m.audit) == 0 {
		return []string{m.styles.muted.Render("no audit entries")}
	}
	start := clampInt(m.auditOffset, 0, maxInt(0, len(m.audit)-1))
	out := make([]string, 0, h)
	for i := start; i < len(m.audit) && len(out) < h; i++ {
		e := m.audit[i]
		ts := m.styles.muted.Render(e.Timestamp.Local().Format("15:04"))
		action := m.styles.accent.Render(e.Action)
		name := e.ResourceName
		if name == "" {
			name = e.ResourceType
		}
		line := ts + " " + action + " " + m.styles.row.Render(name)
		out = append(out, truncate(line, w))
	}
	return out
}

// plainValue returns the value cell as plain text (for selected-row
// rendering, where the whole row gets one style).
func plainValue(val string, shown bool, w int) string {
	if shown {
		return truncate(val, w)
	}
	return maskDots
}

// selectStyle returns the row highlight: strong when the pane is focused,
// subtle when it isn't.
func selectStyle(s themeStyles, focused bool) lipgloss.Style {
	if focused {
		return s.rowSel
	}
	return s.rowCur
}

// scrollWindow returns [start,end) of length ≤ h that keeps cursor visible.
func scrollWindow(total, h, cursor int) (int, int) {
	if total <= h {
		return 0, total
	}
	start := cursor - h/2
	if start < 0 {
		start = 0
	}
	if start+h > total {
		start = total - h
	}
	return start, start + h
}

// ---- overlays ----

func (m Model) renderHelpOverlay(h int) string {
	title := m.styles.titleHot.Render("Help") + "\n\n"
	box := m.styles.overlay.Render(title + m.hvp.View())
	placed := lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center, box)
	return clampGrid(placed, m.width, h)
}

func (m Model) renderUnlockOverlay(h int) string {
	title := m.styles.titleHot.Render("Unlock vault")
	prompt := m.styles.muted.Render("enter passphrase, ⏎ to unlock, esc to cancel")
	field := m.unlock.View()
	body := lipgloss.JoinVertical(lipgloss.Left, title, "", field, "", prompt)
	box := m.styles.overlay.Width(clampInt(m.width/2, 28, 50)).Render(body)

	offset := 0
	if m.anim && m.now.Before(m.shakeUntil) {
		// tiny horizontal jitter while the failure flash decays
		t := m.shakeUntil.Sub(m.now)
		if (t/(40*time.Millisecond))%2 == 0 {
			offset = 1
		}
	}
	placed := lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center, box)
	if offset > 0 {
		placed = indentLines(placed, offset)
	}
	return clampGrid(placed, m.width, h)
}

// renderEditOverlay draws the new-key / set-value input modal (--rw).
func (m Model) renderEditOverlay(h int) string {
	var title string
	switch {
	case m.mode == modeNewKey:
		title = "New secret — key name"
	case m.editing:
		title = "Edit " + m.pendingKey
	default:
		title = "New secret — value"
	}
	body := lipgloss.JoinVertical(lipgloss.Left,
		m.styles.titleHot.Render(title), "",
		m.edit.View(), "",
		m.styles.muted.Render("⏎ save · esc cancel"),
	)
	box := m.styles.overlay.Width(clampInt(m.width/2, 30, 60)).Render(body)
	return clampGrid(lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center, box), m.width, h)
}

// renderConfirmOverlay draws the delete-confirmation modal (--rw).
func (m Model) renderConfirmOverlay(h int) string {
	body := lipgloss.JoinVertical(lipgloss.Left,
		m.styles.titleHot.Render("Delete secret"), "",
		m.styles.row.Render("Delete '"+m.confirmKey+"' permanently?"), "",
		m.styles.bad.Render("y")+m.styles.muted.Render(" delete  ·  n / esc cancel"),
	)
	box := m.styles.overlay.Width(clampInt(m.width/2, 30, 56)).Render(body)
	return clampGrid(lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center, box), m.width, h)
}

// clampGrid forces s to exactly h rows, each at least w cells wide. It
// only adds/drops whole lines and pads short lines — never cutting inside
// a line — so ANSI styling stays intact. lipgloss.Place already pads each
// row to w; this guards the row count when a box is taller than h (small
// terminals) so the overlay can never overflow the grid.
func clampGrid(s string, w, h int) string {
	lines := strings.Split(s, "\n")
	blank := strings.Repeat(" ", w)
	out := make([]string, h)
	for i := 0; i < h; i++ {
		if i < len(lines) {
			out[i] = padRight(lines[i], w)
		} else {
			out[i] = blank
		}
	}
	return strings.Join(out, "\n")
}

func indentLines(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}

// humanizeSince renders a coarse "time ago" string.
func humanizeSince(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
