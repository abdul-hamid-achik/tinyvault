package dotenv

import (
	"fmt"
	"strings"
)

// Ref is a parsed tvault:// reference embedded in a dotenv value.
//
// Format: tvault://PROJECT/KEY
// The project segment is optional; tvault://current/KEY and
// tvault:///KEY (empty project) both resolve via the active project at
// runtime. The latter form is the recommended one.
type Ref struct {
	Project string // empty = current project
	Key     string
}

// String returns the canonical tvault:// URI form.
func (r Ref) String() string {
	return fmt.Sprintf("tvault://%s/%s", r.Project, r.Key)
}

// ErrInvalidRef is returned when a string between ${ and } is not a
// well-formed tvault:// URI.
type ErrInvalidRef struct {
	Raw    string
	Reason string
}

func (e *ErrInvalidRef) Error() string {
	return fmt.Sprintf("invalid tvault reference %q: %s", e.Raw, e.Reason)
}

// ParseRef parses a single tvault:// URI. It returns ErrInvalidRef on
// any deviation from the grammar; we do not allow partial success
// because partial references leak into runtime as literal text.
func ParseRef(s string) (Ref, error) {
	const prefix = "tvault://"
	if !strings.HasPrefix(s, prefix) {
		return Ref{}, &ErrInvalidRef{Raw: s, Reason: `missing "tvault://" scheme`}
	}
	body := strings.TrimPrefix(s, prefix)
	if body == "" || strings.Contains(body, " ") || strings.Contains(body, "\n") {
		return Ref{}, &ErrInvalidRef{Raw: s, Reason: "empty or contains whitespace"}
	}
	idx := strings.Index(body, "/")
	if idx < 0 {
		return Ref{Project: "", Key: body}, nil
	}
	project := body[:idx]
	key := body[idx+1:]
	if key == "" {
		return Ref{}, &ErrInvalidRef{Raw: s, Reason: "missing key segment after project"}
	}
	if strings.Contains(key, "/") {
		return Ref{}, &ErrInvalidRef{Raw: s, Reason: "key must be a single segment"}
	}
	return Ref{Project: project, Key: key}, nil
}

// Refs extracts every tvault:// reference in s in left-to-right order.
// Duplicates are preserved (the resolver may want to dedupe). Invalid
// references are returned as ErrInvalidRef-wrapped strings so the caller
// can report them precisely.
func Refs(s string) ([]string, error) {
	var out []string
	i := 0
	for i < len(s) {
		start := strings.Index(s[i:], "${")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(s[start:], "}")
		if end < 0 {
			break
		}
		end += start
		inner := s[start+2 : end]
		if strings.HasPrefix(inner, "tvault://") {
			out = append(out, inner)
		}
		i = end + 1
	}
	return out, nil
}

// Resolve replaces every ${tvault://...} reference in s with the value
// returned by resolver. The resolver receives one Ref at a time.
//
// The substitution is literal: it does not perform shell expansion,
// command substitution, or arithmetic. A value that is itself a URI
// (e.g. an OAuth redirect URL that happens to contain "tvault://") is
// preserved as-is. We only rewrite references that occur between
// "${" and "}".
//
// The resolver is called at most once per unique reference.
func Resolve(s string, resolver func(Ref) (string, error)) (string, error) {
	type span struct{ start, end int }
	var spans []span
	i := 0
	for i < len(s) {
		startIdx := strings.Index(s[i:], "${")
		if startIdx < 0 {
			break
		}
		startIdx += i
		endIdx := strings.Index(s[startIdx:], "}")
		if endIdx < 0 {
			break
		}
		endIdx += startIdx
		inner := s[startIdx+2 : endIdx]
		if strings.HasPrefix(inner, "tvault://") {
			spans = append(spans, span{start: startIdx, end: endIdx})
		}
		i = endIdx + 1
	}
	if len(spans) == 0 {
		return s, nil
	}

	// Resolve each span; we know all are well-formed because the
	// matcher above only kept ${...} with a tvault:// prefix.
	seen := make(map[Ref]string, len(spans))
	for _, sp := range spans {
		ref, perr := ParseRef(s[sp.start+2 : sp.end])
		if perr != nil {
			return "", perr
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		v, err := resolver(ref)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", ref.String(), err)
		}
		seen[ref] = v
	}

	var b strings.Builder
	cursor := 0
	for _, sp := range spans {
		ref, perr := ParseRef(s[sp.start+2 : sp.end])
		if perr != nil {
			return "", perr
		}
		b.WriteString(s[cursor:sp.start])
		b.WriteString(seen[ref])
		cursor = sp.end + 1
	}
	b.WriteString(s[cursor:])
	return b.String(), nil
}

// HasRef reports whether s contains at least one ${tvault://...} reference.
func HasRef(s string) bool {
	refs, err := Refs(s)
	if err != nil {
		return false
	}
	return len(refs) > 0
}
