package studio

import (
	"fmt"
	"sort"
	"strings"
	"time"

	help "charm.land/bubbles/v2/help"
	key "charm.land/bubbles/v2/key"
	spinner "charm.land/bubbles/v2/spinner"
	textinput "charm.land/bubbles/v2/textinput"
	viewport "charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// paneID identifies one of the four panes.
type paneID int

const (
	paneStatus paneID = iota
	paneProjects
	paneSecrets
	paneAudit
	paneCount
)

func (p paneID) title() string {
	switch p {
	case paneStatus:
		return "Status"
	case paneProjects:
		return "Projects"
	case paneSecrets:
		return "Secrets"
	case paneAudit:
		return "Audit"
	default:
		return ""
	}
}

// mode is the current input focus.
type mode int

const (
	modeNormal     mode = iota
	modeFilter          // the filter textinput is focused
	modeUnlock          // the unlock passphrase modal is up
	modeHelp            // the help overlay is up
	modeNewKey          // entering a new secret's key name (--rw)
	modeSetValue        // entering a secret's value, new or edited (--rw)
	modeConfirmDel      // confirming a secret delete (--rw)
	modeDrift           // env drift overlay is up
	modeGroups          // env groups list overlay is up
)

const (
	flashDuration = 320 * time.Millisecond
	pulsePeriod   = 1500 * time.Millisecond
	multiPaneMinW = 90
	multiPaneMinH = 20
	minTermW      = 40
	minTermH      = 10
)

// Options carries the cobra-flag configuration into the model. It is
// exported so the cmd package can build it from flags.
type Options struct {
	Project    string
	SinglePane bool
	NoAnim     bool
	AuditLimit int
	ReadWrite  bool // --rw: enable in-app set/edit/delete (default read-only)
}

// Model is the top-level Bubble Tea model for `tvault studio`.
type Model struct {
	vault *vault.Vault
	opts  Options

	// data
	status      statusData
	projects    []vault.ProjectSnapshot
	allSecrets  []vault.SecretRef // unfiltered, for the view project
	secrets     []vault.SecretRef // filtered view
	audit       []*store.AuditEntry
	viewProject string // project whose secrets are shown

	// reveal
	revealed    map[string]string // "project/key" -> plaintext value
	revealAll   bool
	revealEpoch int // bumped on every wipe; stale in-flight reveals are dropped

	// ui state
	width, height int
	ready         bool
	active        paneID
	mode          mode
	projCursor    int
	secCursor     int
	auditOffset   int
	statusLine    string // transient one-line message in the footer
	lastErr       error
	quitting      bool

	// read-write (--rw) edit state
	rw         bool
	edit       textinput.Model // key/value entry for new/edit
	pendingKey string          // key being created or edited
	editing    bool            // true = editing an existing key, false = new
	confirmKey string          // key pending delete confirmation

	// env-group state
	envGroups      []vault.EnvGroup              // all groups, loaded once
	projGroupIndex map[string]envMembership      // project name → group/env info
	inherited      map[string]vault.InheritedKey // key → inherited status for viewProject
	envDiff        *vault.EnvDiff                // diff for the drift overlay

	// components
	filter textinput.Model
	unlock textinput.Model
	spin   spinner.Model
	hvp    viewport.Model // help overlay
	help   help.Model
	keys   keyMap
	styles themeStyles
	isDark bool

	// animation
	anim       bool
	loading    bool
	animating  bool
	start      time.Time
	now        time.Time
	flashKey   string
	flashUntil time.Time
	shakeUntil time.Time
}

// New builds the initial model. The vault is already open (and possibly
// already unlocked via TVAULT_PASSPHRASE) by the caller.
func New(v *vault.Vault, opts Options) Model {
	fi := textinput.New()
	fi.Placeholder = "filter keys…"
	fi.Prompt = ""

	ui := textinput.New()
	ui.Placeholder = "passphrase"
	ui.EchoMode = textinput.EchoPassword
	ui.Prompt = ""

	ei := textinput.New()
	ei.Prompt = ""

	sp := spinner.New(spinner.WithSpinner(spinner.Dot))

	m := Model{
		vault:    v,
		opts:     opts,
		revealed: make(map[string]string),
		active:   paneSecrets,
		mode:     modeNormal,
		rw:       opts.ReadWrite,
		filter:   fi,
		unlock:   ui,
		edit:     ei,
		spin:     sp,
		hvp:      viewport.New(viewport.WithWidth(80), viewport.WithHeight(20)),
		help:     help.New(),
		keys:     newKeyMap(),
		isDark:   true,
		styles:   newTheme(true),
		anim:     animEnabled(opts.NoAnim),
		loading:  true,
		start:    time.Now(),
		now:      time.Now(),
	}
	if opts.Project != "" {
		m.viewProject = opts.Project
	}
	return m
}

// Init kicks off the background-color query, the initial data load, and
// (if animations are on) the frame ticker + spinner.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{
		tea.RequestBackgroundColor,
		statusCmd(m.vault),
		projectsCmd(m.vault),
		auditCmd(m.vault, m.opts.AuditLimit),
		envGroupsCmd(m.vault),
	}
	if m.viewProject != "" {
		cmds = append(cmds, secretsCmd(m.vault, m.viewProject))
	}
	if m.anim {
		cmds = append(cmds, m.spin.Tick, frameTick())
	}
	return tea.Batch(cmds...)
}

// shouldAnimate reports whether the frame loop needs to keep ticking:
// either the vault is locked (header pulse) or a reveal flash / shake is
// still decaying.
func (m Model) shouldAnimate() bool {
	if !m.anim {
		return false
	}
	if !m.status.unlocked {
		return true
	}
	if m.now.Before(m.flashUntil) || m.now.Before(m.shakeUntil) {
		return true
	}
	return false
}

// ensureAnim returns a frame-tick command if the loop isn't already
// running and animation is warranted.
func (m *Model) ensureAnim() tea.Cmd {
	if m.anim && !m.animating && m.shouldAnimate() {
		m.animating = true
		return frameTick()
	}
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ready = true
		m.relayout()
		return m, nil

	case tea.BackgroundColorMsg:
		m.isDark = msg.IsDark()
		m.styles = newTheme(m.isDark)
		return m, nil

	case spinner.TickMsg:
		if !m.loading {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case frameMsg:
		m.now = time.Time(msg)
		if m.shouldAnimate() {
			return m, frameTick()
		}
		m.animating = false
		return m, nil

	case statusLoadedMsg:
		m.status = statusData(msg)
		switch m.viewProject {
		case "":
			m.viewProject = m.status.currentProject
			if m.viewProject != "" {
				cmds := []tea.Cmd{secretsCmd(m.vault, m.viewProject)}
				if inhCmd := m.loadInheritedForCurrent(); inhCmd != nil {
					cmds = append(cmds, inhCmd)
				}
				return m, tea.Batch(cmds...)
			}
			// No current project: there are no secrets to load, so the
			// initial load is done — stop the loading spinner.
			m.loading = false
		case m.status.currentProject:
			if inhCmd := m.loadInheritedForCurrent(); inhCmd != nil {
				return m, inhCmd
			}
		}
		// ensureAnim mutates m (sets animating); evaluate it before the
		// return so the mutation is captured in the returned model.
		cmd := m.ensureAnim()
		return m, cmd

	case projectsLoadedMsg:
		m.projects = msg.projects
		m.syncProjectCursor()
		return m, nil

	case secretsLoadedMsg:
		if msg.project == m.viewProject {
			m.allSecrets = msg.refs
			m.applyFilter()
			m.loading = false
		}
		return m, nil

	case auditLoadedMsg:
		m.audit = msg.entries
		return m, nil

	case envGroupsLoadedMsg:
		m.envGroups = msg.groups
		m.buildProjGroupIndex()
		// Now that the index is built, load inherited status for the
		// current view project if it's in a group with inheritance.
		if inhCmd := m.loadInheritedForCurrent(); inhCmd != nil {
			return m, inhCmd
		}
		return m, nil

	case inheritedLoadedMsg:
		if msg.group == m.status.envGroup && msg.env == m.status.envName {
			m.inherited = make(map[string]vault.InheritedKey, len(msg.inherited))
			for _, ik := range msg.inherited {
				m.inherited[ik.Key] = ik
			}
			// Merge inherited keys that aren't in the child project into
			// allSecrets so they appear in the Secrets pane with the ← marker.
			existing := make(map[string]bool, len(m.allSecrets))
			for _, r := range m.allSecrets {
				existing[r.Key] = true
			}
			for _, ik := range msg.inherited {
				if !existing[ik.Key] && ik.Source != "missing" {
					m.allSecrets = append(m.allSecrets, vault.SecretRef{
						Project: m.viewProject,
						Key:     ik.Key,
					})
				}
			}
			m.applyFilter()
		}
		return m, nil

	case diffLoadedMsg:
		m.envDiff = msg.diff
		m.mode = modeDrift
		return m, nil

	case diffErrMsg:
		m.lastErr = msg.err
		m.statusLine = msg.context + ": " + msg.err.Error()
		return m, nil

	case revealedMsg:
		// Drop a reveal that was invalidated while in flight: a wipe
		// (esc / pane change / lock / quit / reload / project switch)
		// bumped the epoch, the vault was re-locked, or the user moved to
		// another project. Without this guard a late reveal could
		// resurrect a plaintext value after it was supposed to be gone.
		if msg.epoch != m.revealEpoch || !m.status.unlocked || msg.project != m.viewProject {
			return m, nil
		}
		m.revealed[msg.project+"/"+msg.key] = msg.value
		m.flashKey = msg.key
		m.flashUntil = time.Now().Add(flashDuration)
		m.statusLine = "revealed " + msg.key
		cmd := m.ensureAnim()
		return m, cmd

	case copiedMsg:
		m.statusLine = "copied " + msg.key + " to clipboard"
		return m, tea.SetClipboard(msg.value)

	case mutationDoneMsg:
		// A write/delete changed the data: re-mask and reload everything
		// (counts, the secrets list, and the audit pane all move).
		m.wipeRevealed()
		m.statusLine = msg.action + " " + msg.key
		m.loading = true
		return m, tea.Batch(m.reloadCmds()...)

	case errMsg:
		m.lastErr = msg.err
		m.statusLine = msg.context + ": " + msg.err.Error()
		m.loading = false
		if m.mode == modeUnlock {
			m.shakeUntil = time.Now().Add(flashDuration)
			cmd := m.ensureAnim()
			return m, cmd
		}
		return m, nil

	case tea.MouseWheelMsg:
		return m.handleWheel(msg)

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

// handleWheel maps the mouse wheel to scrolling: it moves the selection
// in the focused pane, or scrolls the help overlay when it is open.
func (m Model) handleWheel(msg tea.MouseWheelMsg) (tea.Model, tea.Cmd) {
	if m.mode == modeHelp {
		var cmd tea.Cmd
		m.hvp, cmd = m.hvp.Update(msg)
		return m, cmd
	}
	if m.mode != modeNormal {
		return m, nil
	}
	switch msg.Button {
	case tea.MouseWheelUp:
		return m.moveCursor(-1)
	case tea.MouseWheelDown:
		return m.moveCursor(1)
	}
	return m, nil
}

// copiedMsg is emitted by the copy command once a value is decrypted and
// ready to be placed on the clipboard.
type copiedMsg struct {
	key   string
	value string
}

func copyCmd(v *vault.Vault, project, key string) tea.Cmd {
	return func() tea.Msg {
		val, err := revealSecret(v, project, key)
		if err != nil {
			return errMsg{context: "copy " + key, err: err}
		}
		return copiedMsg{key: key, value: val}
	}
}

// copyInheritedCmd resolves a key through the inheritance chain and copies
// the value to the clipboard.
func copyInheritedCmd(v *vault.Vault, groupName, envName, key, childProject string) tea.Cmd {
	return func() tea.Msg {
		val, _, err := v.ResolveKey(groupName, envName, key)
		if err != nil {
			return errMsg{context: "copy " + key, err: err}
		}
		//nolint:errcheck // audit is best-effort
		v.AppendAudit(&store.AuditEntry{
			Action:       "secret.read",
			ResourceType: "secret",
			ResourceName: key,
			Timestamp:    time.Now().UTC(),
			Metadata:     map[string]any{"project": childProject, "source": "tui", "resolved_via": groupName + "/" + envName},
		})
		return copiedMsg{key: key, value: val}
	}
}

func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch m.mode {
	case modeHelp:
		switch {
		case key.Matches(msg, m.keys.Help), key.Matches(msg, m.keys.Escape), key.Matches(msg, m.keys.Quit):
			m.mode = modeNormal
			return m, nil
		}
		var cmd tea.Cmd
		m.hvp, cmd = m.hvp.Update(msg)
		return m, cmd

	case modeFilter:
		switch msg.String() {
		case "esc":
			m.mode = modeNormal
			m.filter.Blur()
			m.filter.SetValue("")
			m.applyFilter()
			return m, nil
		case "enter":
			m.mode = modeNormal
			m.filter.Blur()
			return m, nil
		}
		var cmd tea.Cmd
		m.filter, cmd = m.filter.Update(msg)
		m.applyFilter()
		return m, cmd

	case modeUnlock:
		switch msg.String() {
		case "esc":
			m.mode = modeNormal
			m.unlock.Blur()
			m.unlock.SetValue("")
			return m, nil
		case "enter":
			pass := m.unlock.Value()
			m.unlock.SetValue("")
			m.unlock.Blur()
			m.mode = modeNormal
			if err := m.vault.Unlock(pass); err != nil {
				m.lastErr = err
				m.statusLine = "unlock failed: " + err.Error()
				m.shakeUntil = time.Now().Add(flashDuration)
				cmd := m.ensureAnim()
				return m, cmd
			}
			m.statusLine = "vault unlocked"
			return m, tea.Batch(statusCmd(m.vault), auditCmd(m.vault, m.opts.AuditLimit))
		}
		var cmd tea.Cmd
		m.unlock, cmd = m.unlock.Update(msg)
		return m, cmd

	case modeNewKey:
		switch msg.String() {
		case "esc":
			m.cancelEdit()
			return m, nil
		case "enter":
			key := strings.TrimSpace(m.edit.Value())
			if key == "" {
				m.statusLine = "key cannot be empty"
				return m, nil
			}
			m.pendingKey = key
			m.mode = modeSetValue
			m.edit.SetValue("")
			m.edit.Placeholder = "value for " + key
			return m, nil
		}
		var cmd tea.Cmd
		m.edit, cmd = m.edit.Update(msg)
		return m, cmd

	case modeSetValue:
		switch msg.String() {
		case "esc":
			m.cancelEdit()
			return m, nil
		case "enter":
			key, proj, val := m.pendingKey, m.viewProject, m.edit.Value()
			m.cancelEdit()
			return m, setSecretCmd(m.vault, proj, key, val)
		}
		var cmd tea.Cmd
		m.edit, cmd = m.edit.Update(msg)
		return m, cmd

	case modeConfirmDel:
		switch msg.String() {
		case "y", "Y":
			key, proj := m.confirmKey, m.viewProject
			m.confirmKey = ""
			m.mode = modeNormal
			return m, deleteSecretCmd(m.vault, proj, key)
		case "n", "N", "esc":
			m.confirmKey = ""
			m.mode = modeNormal
		}
		return m, nil

	case modeDrift, modeGroups:
		switch msg.String() {
		case "esc", "q", "?":
			m.mode = modeNormal
		}
		return m, nil

	default:
		// modeNormal — handled below.
	}

	return m.handleNormalKey(msg)
}

func (m Model) handleNormalKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		m.quitting = true
		m.wipeRevealed()
		return m, tea.Quit

	case key.Matches(msg, m.keys.Help):
		m.mode = modeHelp
		m.hvp.SetContent(renderHelp(m.hvp.Width(), m.isDark))
		m.hvp.GotoTop()
		return m, nil

	case key.Matches(msg, m.keys.Pane1):
		m.focusPane(paneStatus)
		return m, nil
	case key.Matches(msg, m.keys.Pane2):
		m.focusPane(paneProjects)
		return m, nil
	case key.Matches(msg, m.keys.Pane3):
		m.focusPane(paneSecrets)
		return m, nil
	case key.Matches(msg, m.keys.Pane4):
		m.focusPane(paneAudit)
		return m, nil

	case key.Matches(msg, m.keys.NextPane), key.Matches(msg, m.keys.Right):
		m.focusPane((m.active + 1) % paneCount)
		return m, nil
	case key.Matches(msg, m.keys.PrevPane), key.Matches(msg, m.keys.Left):
		m.focusPane((m.active - 1 + paneCount) % paneCount)
		return m, nil

	case key.Matches(msg, m.keys.Up):
		return m.moveCursor(-1)
	case key.Matches(msg, m.keys.Down):
		return m.moveCursor(1)

	case key.Matches(msg, m.keys.Enter):
		if m.active == paneProjects && len(m.projects) > 0 {
			m.focusPane(paneSecrets)
			m.viewProject = m.projects[m.projCursor].Name
			m.secCursor = 0
			m.loading = true
			return m, secretsCmd(m.vault, m.viewProject)
		}
		return m, nil

	case key.Matches(msg, m.keys.Filter):
		m.focusPane(paneSecrets)
		m.mode = modeFilter
		return m, m.filter.Focus()

	case key.Matches(msg, m.keys.Reveal):
		return m.revealCurrent()

	case key.Matches(msg, m.keys.RevealAll):
		return m.revealAllCurrent()

	case key.Matches(msg, m.keys.Copy):
		return m.copyCurrent()

	case msg.String() == "n" && m.rw:
		return m.startNewSecret()
	case msg.String() == "e" && m.rw && m.active == paneSecrets:
		return m.startEditSecret()
	case msg.String() == "d" && m.rw && m.active == paneSecrets:
		return m.startDeleteSecret()

	case key.Matches(msg, m.keys.Escape):
		m.wipeRevealed()
		m.statusLine = ""
		return m, nil

	case key.Matches(msg, m.keys.CycleEnv):
		cmd, ok := m.cycleEnv()
		if !ok {
			m.statusLine = "current project is not in an env group"
			return m, nil
		}
		em, _ := m.envMembershipFor(m.viewProject)
		m.statusLine = "env: " + em.env + " (" + m.viewProject + ")"
		return m, cmd

	case key.Matches(msg, m.keys.Drift):
		em, ok := m.envMembershipFor(m.viewProject)
		if !ok {
			m.statusLine = "current project is not in an env group"
			return m, nil
		}
		m.statusLine = "loading drift…"
		return m, diffCmd(m.vault, em.group)

	case key.Matches(msg, m.keys.ListGroups):
		m.mode = modeGroups
		return m, nil

	case key.Matches(msg, m.keys.Unlock):
		if m.status.unlocked {
			m.statusLine = "vault already unlocked"
			return m, nil
		}
		m.mode = modeUnlock
		return m, m.unlock.Focus()

	case key.Matches(msg, m.keys.Lock):
		m.vault.Lock()
		m.wipeRevealed()
		m.statusLine = "vault locked"
		cmd := m.ensureAnim()
		return m, tea.Batch(statusCmd(m.vault), cmd)

	case key.Matches(msg, m.keys.Reload):
		m.wipeRevealed() // re-mask everything; the data is being refetched
		m.loading = true
		m.statusLine = "reloading…"
		cmds := m.reloadCmds()
		if m.anim {
			cmds = append(cmds, m.spin.Tick)
		}
		return m, tea.Batch(cmds...)

	case key.Matches(msg, m.keys.Redraw):
		return m, tea.ClearScreen
	}

	return m, nil
}

// focusPane switches the active pane. Per the documented security model,
// changing panes wipes every revealed value from memory — revealed
// secrets never outlive the secrets view.
func (m *Model) focusPane(p paneID) {
	if p == m.active {
		return
	}
	m.wipeRevealed()
	m.active = p
}

// reloadCmds returns the commands that refresh all panes from disk.
func (m Model) reloadCmds() []tea.Cmd {
	cmds := []tea.Cmd{
		statusCmd(m.vault),
		projectsCmd(m.vault),
		auditCmd(m.vault, m.opts.AuditLimit),
		envGroupsCmd(m.vault),
	}
	if m.viewProject != "" {
		cmds = append(cmds, secretsCmd(m.vault, m.viewProject))
	}
	return cmds
}

// cancelEdit leaves any --rw edit mode and clears the input.
func (m *Model) cancelEdit() {
	m.mode = modeNormal
	m.edit.Blur()
	m.edit.SetValue("")
	m.pendingKey = ""
	m.editing = false
}

// startNewSecret begins creating a new secret (--rw): key entry first.
func (m Model) startNewSecret() (tea.Model, tea.Cmd) {
	if !m.status.unlocked {
		m.statusLine = "vault is locked — press u to unlock"
		return m, nil
	}
	m.focusPane(paneSecrets)
	m.editing = false
	m.pendingKey = ""
	m.mode = modeNewKey
	m.edit.SetValue("")
	m.edit.Placeholder = "new key name"
	m.edit.EchoMode = textinput.EchoNormal
	return m, m.edit.Focus()
}

// startEditSecret edits the selected secret's value (--rw). It decrypts
// the current value to prefill the input — an audited read.
func (m Model) startEditSecret() (tea.Model, tea.Cmd) {
	ref, ok := m.currentSecret()
	if !ok {
		return m, nil
	}
	if !m.status.unlocked {
		m.statusLine = "vault is locked — press u to unlock"
		return m, nil
	}
	val, err := revealSecret(m.vault, ref.Project, ref.Key)
	if err != nil {
		m.statusLine = "edit " + ref.Key + ": " + err.Error()
		return m, nil
	}
	m.editing = true
	m.pendingKey = ref.Key
	m.mode = modeSetValue
	m.edit.EchoMode = textinput.EchoNormal
	m.edit.SetValue(val)
	m.edit.Placeholder = "value for " + ref.Key
	m.edit.CursorEnd()
	return m, m.edit.Focus()
}

// startDeleteSecret asks to confirm deleting the selected secret (--rw).
func (m Model) startDeleteSecret() (tea.Model, tea.Cmd) {
	ref, ok := m.currentSecret()
	if !ok {
		return m, nil
	}
	if !m.status.unlocked {
		m.statusLine = "vault is locked — press u to unlock"
		return m, nil
	}
	m.confirmKey = ref.Key
	m.mode = modeConfirmDel
	return m, nil
}

// moveCursor moves the selection within the active pane.
func (m Model) moveCursor(delta int) (tea.Model, tea.Cmd) {
	switch m.active {
	case paneProjects:
		if len(m.projects) == 0 {
			return m, nil
		}
		m.projCursor = clampInt(m.projCursor+delta, 0, len(m.projects)-1)
		// Live-preview the highlighted project's secrets.
		p := m.projects[m.projCursor].Name
		if p != m.viewProject {
			m.viewProject = p
			m.secCursor = 0
			return m, secretsCmd(m.vault, p)
		}
	case paneSecrets:
		if len(m.secrets) == 0 {
			return m, nil
		}
		m.secCursor = clampInt(m.secCursor+delta, 0, len(m.secrets)-1)
	case paneAudit:
		m.auditOffset = clampInt(m.auditOffset+delta, 0, maxInt(0, len(m.audit)-1))
	default:
		// status pane has no cursor to move
	}
	return m, nil
}

func (m Model) revealCurrent() (tea.Model, tea.Cmd) {
	ref, ok := m.currentSecret()
	if !ok {
		return m, nil
	}
	if !m.status.unlocked {
		m.statusLine = "vault is locked — press u to unlock"
		return m, nil
	}
	// For inherited keys (not stored in the child project), use ResolveKey
	// to resolve through the inheritance chain.
	if ik, isInherited := m.inherited[ref.Key]; isInherited && strings.HasPrefix(ik.Source, "inherited:") {
		return m, revealInheritedCmd(m.vault, m.status.envGroup, m.status.envName, ref.Key, ref.Project, m.revealEpoch)
	}
	return m, revealCmd(m.vault, ref.Project, ref.Key, m.revealEpoch)
}

func (m Model) revealAllCurrent() (tea.Model, tea.Cmd) {
	if !m.status.unlocked {
		m.statusLine = "vault is locked — press u to unlock"
		return m, nil
	}
	if len(m.secrets) == 0 {
		return m, nil
	}
	var cmds []tea.Cmd
	for _, ref := range m.secrets {
		if _, done := m.revealed[ref.Project+"/"+ref.Key]; done {
			continue
		}
		cmds = append(cmds, revealCmd(m.vault, ref.Project, ref.Key, m.revealEpoch))
	}
	m.revealAll = true
	return m, tea.Batch(cmds...)
}

func (m Model) copyCurrent() (tea.Model, tea.Cmd) {
	ref, ok := m.currentSecret()
	if !ok {
		return m, nil
	}
	if !m.status.unlocked {
		m.statusLine = "vault is locked — press u to unlock"
		return m, nil
	}
	if val, done := m.revealed[ref.Project+"/"+ref.Key]; done {
		m.statusLine = "copied " + ref.Key + " to clipboard"
		return m, tea.SetClipboard(val)
	}
	// For inherited keys, resolve through the inheritance chain.
	if ik, isInherited := m.inherited[ref.Key]; isInherited && strings.HasPrefix(ik.Source, "inherited:") {
		return m, copyInheritedCmd(m.vault, m.status.envGroup, m.status.envName, ref.Key, ref.Project)
	}
	return m, copyCmd(m.vault, ref.Project, ref.Key)
}

// currentSecret returns the secret under the cursor, if any.
func (m Model) currentSecret() (vault.SecretRef, bool) {
	if len(m.secrets) == 0 || m.secCursor < 0 || m.secCursor >= len(m.secrets) {
		return vault.SecretRef{}, false
	}
	return m.secrets[m.secCursor], true
}

// applyFilter recomputes m.secrets from m.allSecrets and the filter text.
// The result is sorted by key so that m.secrets IS the display order —
// the cursor (m.secCursor) and the rendered rows can never disagree.
func (m *Model) applyFilter() {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	out := make([]vault.SecretRef, 0, len(m.allSecrets))
	for _, r := range m.allSecrets {
		if q == "" || strings.Contains(strings.ToLower(r.Key), q) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	m.secrets = out
	m.secCursor = clampInt(m.secCursor, 0, maxInt(0, len(m.secrets)-1))
}

// syncProjectCursor positions the cursor on the view project after a
// projects reload.
func (m *Model) syncProjectCursor() {
	if m.viewProject == "" {
		return
	}
	for i, p := range m.projects {
		if p.Name == m.viewProject {
			m.projCursor = i
			return
		}
	}
	m.projCursor = clampInt(m.projCursor, 0, maxInt(0, len(m.projects)-1))
}

// wipeRevealed clears every decrypted value from memory and bumps the
// reveal epoch so any reveal command still in flight is dropped when it
// returns (it cannot resurrect a value after the wipe).
func (m *Model) wipeRevealed() {
	for k := range m.revealed {
		delete(m.revealed, k)
	}
	m.revealAll = false
	m.flashKey = ""
	m.revealEpoch++
}

// secretCount sums secrets across all projects (for the header/status).
func (m Model) secretCount() int {
	n := 0
	for _, p := range m.projects {
		n += p.SecretCount
	}
	return n
}

// buildProjGroupIndex builds a project → (group, env) lookup from the
// loaded env groups. Called once after env groups are loaded.
func (m *Model) buildProjGroupIndex() {
	m.projGroupIndex = make(map[string]envMembership)
	for _, g := range m.envGroups {
		for _, e := range g.Environments {
			m.projGroupIndex[e.Project] = envMembership{group: g.Name, env: e.Name}
		}
	}
}

// envMembershipFor returns the group/env info for a project, if any.
func (m Model) envMembershipFor(project string) (envMembership, bool) {
	em, ok := m.projGroupIndex[project]
	return em, ok
}

// cycleEnv switches to the next environment's project within the same
// group as the current view project. Returns a command to load the new
// project's secrets, or nil if the project is not in a group.
func (m *Model) cycleEnv() (tea.Cmd, bool) {
	em, ok := m.envMembershipFor(m.viewProject)
	if !ok {
		return nil, false
	}
	// Find the group and cycle to the next environment.
	for _, g := range m.envGroups {
		if g.Name != em.group {
			continue
		}
		for i, e := range g.Environments {
			if e.Name != em.env {
				continue
			}
			next := g.Environments[(i+1)%len(g.Environments)]
			m.viewProject = next.Project
			m.secCursor = 0
			m.wipeRevealed()
			m.loading = true
			m.inherited = nil
			cmds := []tea.Cmd{secretsCmd(m.vault, next.Project)}
			// Load inherited status if the new env has inheritance.
			if g.Inheritance != nil {
				if _, hasInh := g.Inheritance[next.Name]; hasInh {
					cmds = append(cmds, inheritedCmd(m.vault, g.Name, next.Name))
				}
			}
			return tea.Batch(cmds...), true
		}
	}
	return nil, false
}

// loadInheritedForCurrent issues a command to load the inherited status
// for the current view project, if it is in a group with inheritance.
func (m Model) loadInheritedForCurrent() tea.Cmd {
	em, ok := m.envMembershipFor(m.viewProject)
	if !ok {
		return nil
	}
	for _, g := range m.envGroups {
		if g.Name != em.group {
			continue
		}
		if g.Inheritance != nil {
			if _, hasInh := g.Inheritance[em.env]; hasInh {
				return inheritedCmd(m.vault, em.group, em.env)
			}
		}
	}
	return nil
}

// lastWrite returns the most recent project UpdatedAt, or zero time.
func (m Model) lastWrite() time.Time {
	var t time.Time
	for _, p := range m.projects {
		if p.UpdatedAt.After(t) {
			t = p.UpdatedAt
		}
	}
	return t
}

// relayout resizes child components to the current terminal size.
func (m *Model) relayout() {
	// Help overlay viewport. The overlay box adds a rounded border (2) +
	// vertical padding (2) + a 2-row title around the viewport (6 rows of
	// chrome), and a border (2) + horizontal padding (6) around its width.
	// The body region the overlay is placed into is bodyH = m.height-3, so
	// size the viewport to bodyH-6 = m.height-9 to fill it without
	// overflowing (clampGrid is the final backstop on tiny terminals).
	w := maxInt(20, m.width-14)
	h := maxInt(3, m.height-9)
	m.hvp.SetWidth(w)
	m.hvp.SetHeight(h)
	m.help.SetWidth(m.width)
	m.filter.SetWidth(maxInt(10, m.width/3))
	m.unlock.SetWidth(maxInt(10, m.width/3))
	// The --rw edit modal box is overlay.Width(clampInt(width/2,30,60)); the
	// overlay chrome is a border (2) + horizontal padding (6) = 8, so size the
	// input to the box's inner width. Without a width the textinput renders
	// only the cursor cell — the placeholder hint never shows, and a long value
	// could overflow the box; with it, the placeholder shows and long values
	// scroll within the field.
	m.edit.SetWidth(maxInt(10, clampInt(m.width/2, 30, 60)-8))
	if m.mode == modeHelp {
		m.hvp.SetContent(renderHelp(w, m.isDark))
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// truncate cuts s to w display cells, adding an ellipsis if it overflows.
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	r := []rune(s)
	if w == 1 {
		return "…"
	}
	for len(r) > 0 && lipgloss.Width(string(r))+1 > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// padRight pads s with spaces to width w (no-op if already wider).
func padRight(s string, w int) string {
	d := w - lipgloss.Width(s)
	if d <= 0 {
		return s
	}
	return s + strings.Repeat(" ", d)
}

var _ = fmt.Sprintf
