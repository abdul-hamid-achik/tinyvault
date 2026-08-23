package mcp

import "github.com/abdul-hamid-achik/tinyvault/internal/redact"

// redactSecrets replaces literal secret values in subprocess output.
// See internal/redact: values of 3 characters or fewer are not redacted.
func redactSecrets(output string, secrets map[string]string) string {
	return redact.Literal(output, secrets)
}
