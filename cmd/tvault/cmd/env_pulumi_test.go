package cmd

import (
	"strings"
	"testing"
)

func TestShellArgQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"dop_v1_abc", "dop_v1_abc"},                   // safe set: unquoted
		{"us-east-1", "us-east-1"},                     // hyphen safe
		{"postgres://u:p@h/db", "postgres://u:p@h/db"}, // :/@. all safe
		{"has space", "'has space'"},                   // space → quote
		{"glob?x*", "'glob?x*'"},                       // glob chars → quote
		{"a;b|c&d", "'a;b|c&d'"},                       // shell metacharacters → quote
		{"it's", `'it'\''s'`},                          // embedded single quote
		{"", "''"},                                     // empty → ''
		{"$HOME`x`", "'$HOME`x`'"},                     // expansion chars → quote
	}
	for _, c := range cases {
		if got := shellArgQuote(c.in); got != c.want {
			t.Errorf("shellArgQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func resetEnvFlags(t *testing.T) {
	t.Helper()
	f, ex, stack := envFormat, envExport, envPulumiStack
	t.Cleanup(func() { envFormat, envExport, envPulumiStack = f, ex, stack })
}

func TestEnvPulumiConfigFormat(t *testing.T) {
	resetEnvFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "DIGITALOCEAN_TOKEN", "dop_v1_abc")
	setVersionsForCLI(t, vaultPath, "NUXT_DATABASE_URL", "postgres://u:p@h/db?x=1") // needs quoting

	envFormat, envPulumiStack = "pulumi-config", "prod"
	out := captureStdout(t, func() {
		if err := runEnv(nil, nil); err != nil {
			t.Fatalf("runEnv pulumi-config: %v", err)
		}
	})

	got := string(out)
	wantLines := []string{
		"pulumi config set --secret --stack prod DIGITALOCEAN_TOKEN dop_v1_abc",
		"pulumi config set --secret --stack prod NUXT_DATABASE_URL 'postgres://u:p@h/db?x=1'",
	}
	for _, want := range wantLines {
		if !strings.Contains(got, want) {
			t.Errorf("missing line:\n  %s\nin output:\n%s", want, got)
		}
	}
	// Keys are sorted, so DIGITALOCEAN_TOKEN precedes NUXT_DATABASE_URL.
	if strings.Index(got, "DIGITALOCEAN_TOKEN") > strings.Index(got, "NUXT_DATABASE_URL") {
		t.Errorf("keys not sorted in output:\n%s", got)
	}
}

func TestEnvPulumiConfigNoStack(t *testing.T) {
	resetEnvFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "API_KEY", "sk-123")

	envFormat, envPulumiStack = "pulumi-config", ""
	out := captureStdout(t, func() {
		if err := runEnv(nil, nil); err != nil {
			t.Fatalf("runEnv pulumi-config: %v", err)
		}
	})

	got := strings.TrimSpace(string(out))
	if got != "pulumi config set --secret API_KEY sk-123" {
		t.Errorf("no-stack output = %q", got)
	}
	if strings.Contains(got, "--stack") {
		t.Errorf("did not expect --stack with no stack set: %q", got)
	}
}
