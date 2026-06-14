package cmd

import (
	"encoding/json"
	"os"
)

// writeJSON encodes v as indented JSON to stdout. Shared by commands that
// support --json so the shape and indentation stay consistent.
func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
