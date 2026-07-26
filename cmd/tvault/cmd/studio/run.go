package studio

import (
	tea "charm.land/bubbletea/v2"
)

// Run builds the model and runs the Bubble Tea program against the real
// terminal. The session may be locked (the TUI unlocks in-app with 'u') or
// already carry a KEK when the caller unlocked it via TVAULT_PASSPHRASE.
//
// Run does not close the session — the caller owns its lifecycle, and must
// Close it so the cached KEK is zeroed on every exit path.
func Run(sess *Session, opts Options) error {
	p := tea.NewProgram(New(sess, opts))
	_, err := p.Run()
	return err
}
