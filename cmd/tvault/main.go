// Package main is the entry point for the TinyVault CLI.
package main

import (
	"os"

	"github.com/abdul-hamid-achik/tinyvault/cmd/tvault/cmd"
)

// Build-time variables, set by goreleaser via -ldflags "-X main.version=..."
// so the binary can self-report its version, commit, and build date.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	if err := cmd.Execute(); err != nil {
		// Deterministic, meaningful exit codes (see cmd/exit.go) so
		// scripts/agents can branch on the failure kind. cobra has already
		// printed the error to stderr.
		os.Exit(cmd.ExitCode(err))
	}
}
