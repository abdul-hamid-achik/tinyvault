// Package redact replaces literal secret values in captured output.
//
// This is a safety net, not a control: values of 3 characters or fewer are
// left alone (too many false positives), and any transformation (base64,
// split across writes, re-casing) bypasses matching. Callers that stream
// to a terminal should keep the default unredacted path unless the user
// opts in.
package redact

import (
	"io"
	"strings"
)

// Literal replaces any occurrence of a secret value longer than 3 characters
// with [REDACTED:key]. Short values are left unchanged.
func Literal(output string, secrets map[string]string) string {
	for key, value := range secrets {
		if len(value) > 3 {
			output = strings.ReplaceAll(output, value, "[REDACTED:"+key+"]")
		}
	}
	return output
}

// Writer wraps w so each Write() redacts literal secret values before
// forwarding. A value split across two Write calls is not redacted.
func Writer(w io.Writer, secrets map[string]string) io.Writer {
	return &writer{dst: w, secrets: secrets}
}

type writer struct {
	dst     io.Writer
	secrets map[string]string
}

func (w *writer) Write(p []byte) (int, error) {
	out := Literal(string(p), w.secrets)
	if _, err := w.dst.Write([]byte(out)); err != nil {
		return 0, err
	}
	return len(p), nil
}
