package mcp

import "strings"

// redactSecrets replaces any occurrence of a secret value in output with
// [REDACTED:key]. Values of 3 characters or fewer are not redacted to
// avoid excessive false positives.
func redactSecrets(output string, secrets map[string]string) string {
	for key, value := range secrets {
		if len(value) > 3 {
			output = strings.ReplaceAll(output, value, "[REDACTED:"+key+"]")
		}
	}
	return output
}
