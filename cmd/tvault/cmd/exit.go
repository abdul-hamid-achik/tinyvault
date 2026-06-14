package cmd

import (
	"errors"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// Exit codes. 0/1 are the usual success/generic-failure; the rest let
// scripts and agents branch on *why* a command failed without parsing
// stderr. They are derived from the vault sentinel errors, which commands
// return wrapped with %w, so errors.Is sees through the wrapping.
const (
	ExitOK              = 0
	ExitError           = 1 // generic failure
	ExitLocked          = 3 // vault is locked
	ExitNotFound        = 4 // secret or project not found
	ExitNotInitialized  = 5 // no vault — run 'tvault init'
	ExitWrongPassphrase = 6 // unlock failed
)

// ExitCode maps an error returned from Execute() to a process exit code.
// main() calls this so the exit status is deterministic and meaningful.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, vault.ErrLocked):
		return ExitLocked
	case errors.Is(err, vault.ErrNotInitialized):
		return ExitNotInitialized
	case errors.Is(err, vault.ErrWrongPassphrase):
		return ExitWrongPassphrase
	case errors.Is(err, vault.ErrSecretNotFound), errors.Is(err, vault.ErrProjectNotFound):
		return ExitNotFound
	default:
		return ExitError
	}
}
