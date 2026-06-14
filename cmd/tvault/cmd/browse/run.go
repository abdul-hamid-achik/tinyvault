package browse

import (
	tea "charm.land/bubbletea/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// Run builds the model and runs the Bubble Tea program against the real
// terminal. The vault must already be open; it may be locked (the TUI
// unlocks in-app) or already unlocked (e.g. via TVAULT_PASSPHRASE).
//
// Run does not close the vault — the caller owns its lifecycle.
func Run(v *vault.Vault, opts Options) error {
	p := tea.NewProgram(New(v, opts))
	_, err := p.Run()
	return err
}
