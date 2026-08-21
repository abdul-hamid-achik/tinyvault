package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// jsonSecretsForRoundTrip is the fixture used by env/export JSON tests:
// control bytes (\r, NUL, \t, \n), HTML-sensitive chars, and unsorted keys.
func jsonSecretsForRoundTrip() map[string]string {
	return map[string]string{
		"Z_LAST":  "z",
		"A_FIRST": "a",
		"CTRL":    "line1\r\nline2\tend\x00nul",
		"AMP":     "a&b<c>d",
	}
}

func storeJSONRoundTripSecrets(t *testing.T, vaultPath string) map[string]string {
	t.Helper()
	secrets := jsonSecretsForRoundTrip()
	v := openTestVault(t, vaultPath)
	for k, val := range secrets {
		if err := v.SetSecret("default", k, val); err != nil {
			t.Fatal(err)
		}
	}
	v.Close()
	return secrets
}

func assertJSONRoundTrip(t *testing.T, raw []byte, want map[string]string) {
	t.Helper()
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	for k, wantVal := range want {
		if got[k] != wantVal {
			t.Errorf("%s: got %q, want %q", k, got[k], wantVal)
		}
	}
	body := string(raw)
	if strings.Contains(body, `\u0026`) {
		t.Errorf("HTML-escaped ampersand:\n%s", body)
	}
}

// TestRunEnvJSONRoundTripControlBytes drives `tvault env --format json`
// through the real command path, including \r, NUL, and & < >.
func TestRunEnvJSONRoundTripControlBytes(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	want := storeJSONRoundTripSecrets(t, vaultPath)

	oldFormat := envFormat
	envFormat = "json"
	defer func() { envFormat = oldFormat }()

	out := captureStdout(t, func() {
		if err := runEnv(nil, nil); err != nil {
			t.Fatalf("runEnv: %v", err)
		}
	})
	assertJSONRoundTrip(t, out, want)
}

// TestRunExportJSONRoundTripControlBytes is the export equivalent,
// covering stdout and -o.
func TestRunExportJSONRoundTripControlBytes(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	want := storeJSONRoundTripSecrets(t, vaultPath)

	oldFormat, oldOut := exportFormat, exportOutput
	defer func() { exportFormat, exportOutput = oldFormat, oldOut }()

	exportFormat, exportOutput = "json", ""
	out := captureStdout(t, func() {
		if err := runExport(nil, nil); err != nil {
			t.Fatalf("runExport stdout: %v", err)
		}
	})
	assertJSONRoundTrip(t, out, want)

	outPath := filepath.Join(t.TempDir(), "secrets.json")
	exportOutput = outPath
	if err := runExport(nil, nil); err != nil {
		t.Fatalf("runExport -o: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONRoundTrip(t, data, want)
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

func TestRunEnvOnlyAndPrefixFilterBeforeOutput(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	for key, value := range map[string]string{
		"CHALUPA_DATABASE_URL": "postgres://db",
		"CHALUPA_INGEST_KEY":   "ingest",
		"UNRELATED_TOKEN":      "must-not-be-emitted",
	} {
		if err := v.SetSecret("default", key, value); err != nil {
			t.Fatal(err)
		}
	}
	v.Close()

	oldFormat, oldOnly, oldPrefix := envFormat, envOnly, envPrefix
	envFormat, envOnly, envPrefix = "dotenv", []string{"UNRELATED_TOKEN"}, "CHALUPA_"
	defer func() { envFormat, envOnly, envPrefix = oldFormat, oldOnly, oldPrefix }()

	out := captureStdout(t, func() {
		if err := runEnv(nil, nil); err != nil {
			t.Fatalf("runEnv: %v", err)
		}
	})
	body := string(out)
	for _, key := range []string{"CHALUPA_DATABASE_URL", "CHALUPA_INGEST_KEY", "UNRELATED_TOKEN"} {
		if !strings.Contains(body, key+"=") {
			t.Errorf("filtered output missing %s", key)
		}
	}
}

func TestRunEnvOnlyFailsWhenKeyIsMissing(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	oldOnly, oldPrefix := envOnly, envPrefix
	envOnly, envPrefix = []string{"MISSING"}, ""
	defer func() { envOnly, envPrefix = oldOnly, oldPrefix }()

	if err := runEnv(nil, nil); err == nil || !strings.Contains(err.Error(), "--only key(s) not found") {
		t.Fatalf("runEnv() error = %v, want missing-key error", err)
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
