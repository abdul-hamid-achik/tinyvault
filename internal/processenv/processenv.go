// Package processenv builds child-process environments without forwarding
// TinyVault's own unlock and capability credentials.
package processenv

import "strings"

var controlVariables = map[string]struct{}{
	"TVAULT_PASSPHRASE":   {},
	"TVAULT_IDENTITY_KEY": {},
	"TVAULT_AGENT_TOKEN":  {},
}

// Sanitize removes every TinyVault control-plane credential, including
// duplicate entries. Secret injection must add only application credentials;
// these reserved names are never forwarded to a child process.
func Sanitize(env []string) []string {
	result := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if _, sensitive := controlVariables[name]; sensitive {
			continue
		}
		result = append(result, entry)
	}
	return result
}
