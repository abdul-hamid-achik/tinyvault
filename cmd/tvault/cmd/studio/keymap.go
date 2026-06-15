package studio

import (
	key "charm.land/bubbles/v2/key"
)

// keyMap is the full set of key bindings for the TUI. It implements
// help.KeyMap so the footer and the help overlay can render the same
// bindings without a second source of truth.
type keyMap struct {
	Up        key.Binding
	Down      key.Binding
	Left      key.Binding
	Right     key.Binding
	Pane1     key.Binding
	Pane2     key.Binding
	Pane3     key.Binding
	Pane4     key.Binding
	NextPane  key.Binding
	PrevPane  key.Binding
	Enter     key.Binding
	Filter    key.Binding
	Reveal    key.Binding
	RevealAll key.Binding
	Copy      key.Binding
	Unlock    key.Binding
	Lock      key.Binding
	Reload    key.Binding
	Redraw    key.Binding
	Escape    key.Binding
	Help      key.Binding
	Quit      key.Binding
}

// newKeyMap returns the default bindings (vim + arrows + mnemonics).
func newKeyMap() keyMap {
	return keyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("←/h", "prev pane"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("→/l", "next pane"),
		),
		Pane1: key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "status")),
		Pane2: key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "projects")),
		Pane3: key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "secrets")),
		Pane4: key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "audit")),
		NextPane: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "cycle"),
		),
		PrevPane: key.NewBinding(
			key.WithKeys("shift+tab"),
			key.WithHelp("⇧tab", "cycle back"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("⏎", "open project"),
		),
		Filter: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "filter"),
		),
		Reveal: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "reveal"),
		),
		RevealAll: key.NewBinding(
			key.WithKeys("R"),
			key.WithHelp("R", "reveal all"),
		),
		Copy: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "copy"),
		),
		Unlock: key.NewBinding(
			key.WithKeys("u"),
			key.WithHelp("u", "unlock"),
		),
		Lock: key.NewBinding(
			key.WithKeys("L"),
			key.WithHelp("L", "lock"),
		),
		Reload: key.NewBinding(
			key.WithKeys("ctrl+r"),
			key.WithHelp("^r", "reload"),
		),
		Redraw: key.NewBinding(
			key.WithKeys("ctrl+l"),
			key.WithHelp("^l", "redraw"),
		),
		Escape: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back/hide"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
}

// ShortHelp implements help.KeyMap — the compact footer hint line.
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{
		k.Up, k.Down, k.Right, k.Filter, k.Reveal, k.Copy, k.Help, k.Quit,
	}
}

// FullHelp implements help.KeyMap — the expanded multi-column listing.
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right},
		{k.Pane1, k.Pane2, k.Pane3, k.Pane4, k.NextPane, k.PrevPane},
		{k.Enter, k.Filter, k.Reveal, k.RevealAll, k.Copy},
		{k.Unlock, k.Lock, k.Reload, k.Redraw},
		{k.Escape, k.Help, k.Quit},
	}
}
