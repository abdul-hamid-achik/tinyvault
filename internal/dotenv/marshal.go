package dotenv

import (
	"sort"
	"strings"
)

// Marshal renders a set of key/value pairs as a dotenv document with keys
// sorted for determinism. Values are quoted and escaped so the output round
// trips through ParseBytes — in particular values containing newlines, tabs,
// quotes, backslashes, '#', '$', or leading/trailing spaces are double-quoted
// and escaped rather than emitted raw (which would corrupt the line-based
// format). Callers that build a dotenv body from secret values (env export,
// recipient sealing, git filters) should use this instead of a naive
// "k=v\n" so multi-line or special-character secrets survive the round trip.
func Marshal(values map[string]string) []byte {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(quoteDotenvValue(values[k]))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// quoteDotenvValue returns v safe to place on the right-hand side of a dotenv
// assignment, double-quoting and escaping it when a raw emission would be
// ambiguous or would break the line-based parser.
func quoteDotenvValue(v string) string {
	if v == "" {
		return ""
	}
	// Quote when the value contains anything that the unquoted parser would
	// mangle: quotes/backslashes/'$', whitespace it would trim, an inline-
	// comment '#', or a leading single quote it would treat as a quoted form.
	if !strings.ContainsAny(v, "\"\\$\n\r\t #'") {
		return v
	}

	var b strings.Builder
	b.Grow(len(v) + 2)
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(v[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}
