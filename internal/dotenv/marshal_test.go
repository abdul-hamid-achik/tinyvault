package dotenv

import (
	"strings"
	"testing"
)

func TestMarshalRoundTrip(t *testing.T) {
	cases := map[string]map[string]string{
		"simple":          {"A": "1", "B": "two"},
		"with spaces":     {"MSG": "hello world", "PAD": "  edge  "},
		"with quotes":     {"Q": `she said "hi"`, "BS": `a\b\c`},
		"with dollar":     {"REF": "${tvault://X}", "PRICE": "$5"},
		"with hash":       {"C": "value # not a comment"},
		"multiline":       {"PEM": "-----BEGIN-----\nline1\nline2\n-----END-----"},
		"tabs and cr":     {"T": "a\tb", "R": "a\r\nb"},
		"leading quote":   {"S": "'singley'", "D": `"doubley"`},
		"empty value":     {"EMPTY": "", "FULL": "x"},
		"equals in value": {"EQ": "a=b=c"},
		"unicode":         {"U": "café — naïve — 日本語"},
	}

	for name, secrets := range cases {
		t.Run(name, func(t *testing.T) {
			data := Marshal(secrets)
			pf, err := ParseBytes(".env", data)
			if err != nil {
				t.Fatalf("ParseBytes: %v\n--- marshaled ---\n%s", err, data)
			}
			parsed := make(map[string]string, len(pf.Entries))
			for _, e := range pf.Entries {
				parsed[e.Key] = e.Value
			}
			if len(parsed) != len(secrets) {
				t.Fatalf("got %d entries, want %d\n%s", len(parsed), len(secrets), data)
			}
			for k, want := range secrets {
				got, ok := parsed[k]
				if !ok {
					t.Fatalf("missing key %q in:\n%s", k, data)
				}
				if got != want {
					t.Errorf("key %q: round-trip got %q, want %q\n--- marshaled ---\n%s", k, got, want, data)
				}
			}
		})
	}
}

func TestMarshalIsSortedAndDeterministic(t *testing.T) {
	secrets := map[string]string{"ZED": "1", "ALPHA": "2", "MID": "3"}
	first := string(Marshal(secrets))
	if first != string(Marshal(secrets)) {
		t.Fatal("Marshal is not deterministic")
	}
	lines := strings.Split(strings.TrimSpace(first), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "ALPHA=") ||
		!strings.HasPrefix(lines[1], "MID=") || !strings.HasPrefix(lines[2], "ZED=") {
		t.Errorf("keys not sorted: %q", lines)
	}
}

func TestMarshalEmptyMap(t *testing.T) {
	if out := Marshal(map[string]string{}); len(out) != 0 {
		t.Errorf("empty map should marshal to empty, got %q", out)
	}
}

func TestMarshalSimpleValuesUnquoted(t *testing.T) {
	// Plain values must stay unquoted so the output reads like a normal .env.
	out := string(Marshal(map[string]string{"API_KEY": "sk_live_abc123"}))
	if out != "API_KEY=sk_live_abc123\n" {
		t.Errorf("unexpected quoting of a plain value: %q", out)
	}
}
