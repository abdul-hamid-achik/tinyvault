// Package processenv builds child-process environments without forwarding
// TinyVault's own unlock and capability credentials.
package processenv

import "strings"

// Sanitize removes every TinyVault control-plane variable, including duplicate
// entries. A child receives only its inherited application environment plus
// the explicitly selected vault values; it must never inherit an unlock
// credential, identity, agent capability, routing override, or future
// TVAULT_* control added by a newer CLI.
func Sanitize(env []string) []string {
	result := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "TVAULT_") {
			continue
		}
		result = append(result, entry)
	}
	return result
}
