package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// writeJSON encodes v as indented JSON to stdout. Shared by commands that
// support --json so the shape and indentation stay consistent.
//
// HTML escaping is off so secret values (connection strings, URLs) keep
// literal &, <, and >. encoding/json still escapes control bytes, so the
// result is always valid JSON.
func writeJSON(v any) error {
	return writeJSONTo(os.Stdout, v)
}

// marshalJSON is writeJSON for callers that need the bytes (e.g. export -o).
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeJSONTo(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeJSONTo(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
