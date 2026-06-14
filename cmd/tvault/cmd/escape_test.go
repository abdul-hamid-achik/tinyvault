package cmd

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

// Tests for the .env value escape helpers used by 'tvault env'.

func TestEscapeShellValue(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{"", ""}, // empty string contains no special chars
		{"with space", "'with space'"},
		{"with-dash", "with-dash"},
		{"with$var", "'with$var'"},
		{"with'quote", `'with'"'"'quote'`},
		{"with\nnewline", "'with\nnewline'"},
		{"with\ttab", "'with\ttab'"},
		{"with\"double", `'with"double'`},
		{"with\\back", `'with\back'`},
	}
	for _, tt := range tests {
		got := escapeShellValue(tt.in)
		if got != tt.want {
			t.Errorf("escapeShellValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEscapeDotenvValue(t *testing.T) {
	// escapeDotenvValue quotes a value if it contains any of:
	// "  $  \n  \t  space  hash
	// Inside a quoted value, only " and \ and \n are escaped.
	tests := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{"with space", `"with space"`},   // space triggers quoting
		{"with$var", `"with$var"`},       // $ triggers quoting; $ is not escaped
		{"with\"quote", `"with\"quote"`}, // " triggers quoting and is escaped
		{"with\\back", `"with\\back"`},   // \ triggers quoting and is escaped
		{"with\nnewline", `"with\nnewline"`},
		{"with\ttab", "\"with\t" + "tab\""}, // tab triggers quoting; tab is not escaped
		{"with#hash", `"with#hash"`},        // # triggers quoting; # is not escaped
	}
	for _, tt := range tests {
		got := escapeDotenvValue(tt.in)
		if got != tt.want {
			t.Errorf("escapeDotenvValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEscapeJSONValue(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{"with\"quote", `with\"quote`},
		{"with\\back", `with\\back`},
		{"with\nnewline", `with\nnewline`},
		{"with\ttab", `with\ttab`},
		{"with\rcarriage", `with\rcarriage`}, // control byte: must be escaped (was a bug)
		{"amp&lt<gt>", "amp&lt<gt>"},         // & < > kept literal (no HTML escaping)
	}
	for _, tt := range tests {
		got := escapeJSONValue(tt.in)
		if got != tt.want {
			t.Errorf("escapeJSONValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestEnvJSONValidForControlBytes guards that `tvault env --format json`
// emits VALID JSON even when a value contains control bytes.
func TestEnvJSONValidForControlBytes(t *testing.T) {
	frag := escapeJSONValue("line1\r\nline2\tend")
	doc := []byte(`{"K":"` + frag + `"}`)
	var m map[string]string
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatalf("env json fragment produced invalid JSON: %v (%s)", err, doc)
	}
	if m["K"] != "line1\r\nline2\tend" {
		t.Errorf("round-trip mismatch: %q", m["K"])
	}
}

func TestEscapeYAMLValue(t *testing.T) {
	// YAML quoting rules: quotes are added if the value contains a
	// reserved character OR is reserved word OR parses as a float.
	// The list of reserved chars in this impl:
	//   : # { } [ ] ! | > & * ? - @ ` ' " \ \n \t
	// Plus leading/trailing space.
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"with space", "with space"}, // interior space alone is fine in this impl
		{" space-leading", `" space-leading"`},
		{"trailing-space ", `"trailing-space "`},
		{"true", `"true"`},
		{"false", `"false"`},
		{"null", `"null"`},
		{"~", `"~"`},
		{"yes", `"yes"`},
		{"no", `"no"`},
		{"1.5", `"1.5"`},
		{"0", `"0"`}, // parses as float => quoted
		{"with:colon", `"with:colon"`},
		{"with#hash", `"with#hash"`},
		{"with\"quote", `"with\"quote"`},
		{"with\nnewline", `"with\nnewline"`},
		{"with-amp", `"with-amp"`},
	}
	for _, tt := range tests {
		got := escapeYAMLValue(tt.in)
		if got != tt.want {
			t.Errorf("escapeYAMLValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestRunEnvDotenvRoundTrip verifies that 'tvault env --format=dotenv'
// emits values that the dotenv parser can read back identically.
// This is the most important property for CI consumers: the .env
// file we write must be re-parseable.
func TestRunEnvDotenvRoundTrip(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "PLAIN", "hello"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "WITH_SPACE", "hello world"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "WITH_QUOTE", `she said "hi"`); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "WITH_BACKSLASH", `a\b\c`); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "WITH_NEWLINE", "line1\nline2"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldFormat := envFormat
	envFormat = "dotenv"
	defer func() { envFormat = oldFormat }()

	out := captureStdout(t, func() {
		if err := runEnv(nil, nil); err != nil {
			t.Fatalf("runEnv: %v", err)
		}
	})
	body := string(out)

	parsed, err := dotenv.ParseBytes("test.env", out)
	if err != nil {
		t.Fatalf("dotenv re-parse: %v\nbody: %s", err, body)
	}
	byKey := map[string]string{}
	for _, e := range parsed.Entries {
		byKey[e.Key] = e.Value
	}
	cases := map[string]string{
		"PLAIN":          "hello",
		"WITH_SPACE":     "hello world",
		"WITH_QUOTE":     `she said "hi"`,
		"WITH_BACKSLASH": `a\b\c`,
		"WITH_NEWLINE":   "line1\nline2",
	}
	for k, want := range cases {
		if got := byKey[k]; got != want {
			t.Errorf("round-trip for %q: got %q, want %q", k, got, want)
		}
	}
}

// captureStdout runs fn with os.Stdout pointed at a pipe and
// returns what was written.
func captureStdout(t *testing.T, fn func()) []byte {
	t.Helper()
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()
	fn()
	_ = w.Close()
	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	return buf[:n]
}
