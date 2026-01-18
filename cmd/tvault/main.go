// Package main is the entry point for the TinyVault CLI.
package main

import (
	"os"

	"github.com/abdul-hamid-achik/tinyvault/cmd/tvault/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
