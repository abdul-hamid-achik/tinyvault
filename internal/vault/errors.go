package vault

import "errors"

var (
	// ErrLocked is returned when an operation requires an unlocked vault.
	ErrLocked = errors.New("vault is locked")

	// ErrVaultBusy is returned when the vault database cannot be opened because
	// another tvault process holds bbolt's exclusive lock (e.g. a running
	// `tvault mcp` or `tvault studio`). Distinct from ErrLocked, which means
	// the vault exists but is locked at rest.
	ErrVaultBusy = errors.New("vault is locked by another tvault process " +
		"(the database is open — e.g. a running 'tvault mcp' or 'tvault studio'). " +
		"Stop it, or read secrets via 'tvault agent start'")

	// ErrWrongPassphrase is returned when the passphrase does not match.
	ErrWrongPassphrase = errors.New("wrong passphrase")

	// ErrNotInitialized is returned when the vault directory is not initialized.
	ErrNotInitialized = errors.New("vault not initialized")

	// ErrProjectNotFound is returned when a project cannot be found.
	ErrProjectNotFound = errors.New("project not found")

	// ErrSecretNotFound is returned when a secret cannot be found.
	ErrSecretNotFound = errors.New("secret not found")

	// ErrProjectExists is returned when creating a project that already exists.
	ErrProjectExists = errors.New("project already exists")
)
