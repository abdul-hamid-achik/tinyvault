package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRunWithSecrets_PrefixAndOnly verifies vault_run_with_secrets injects only
// the requested subset. It prints injected env var NAMES (values stay redacted)
// so the assertion never depends on secret values.
func TestRunWithSecrets_PrefixAndOnly(t *testing.T) {
	srv, v := newScratchServer(t) // seeds DB_URL, API_KEY (full policy, exec allowed)
	if err := v.SetSecret("default", "NUXT_A", "alpha-value"); err != nil {
		t.Fatalf("set NUXT_A: %v", err)
	}
	if err := v.SetSecret("default", "NUXT_B", "bravo-value"); err != nil {
		t.Fatalf("set NUXT_B: %v", err)
	}

	ctx := context.Background()
	t1, t2 := sdkmcp.NewInMemoryTransports()
	if _, err := srv.server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	// List which of our candidate keys are present in the child env, by name.
	// We use printenv per-key (POSIX, no grep ANSI color issues) so the
	// test is portable across macOS and Linux.
	const listNames = `for k in NUXT_A NUXT_B DB_URL API_KEY; do printenv "$k" >/dev/null 2>&1 && echo "$k"; done | sort`

	run := func(args map[string]any) []string {
		t.Helper()
		args["command"] = listNames
		res, rerr := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "vault_run_with_secrets", Arguments: args})
		if rerr != nil {
			t.Fatalf("call: %v", rerr)
		}
		var out runResult
		if uerr := json.Unmarshal([]byte(res.Content[0].(*sdkmcp.TextContent).Text), &out); uerr != nil {
			t.Fatalf("unmarshal: %v", uerr)
		}
		if out.ExitCode != 0 {
			t.Fatalf("exit code %d, stderr=%q", out.ExitCode, out.Stderr)
		}
		return strings.Fields(out.Stdout)
	}

	cases := []struct {
		name string
		args map[string]any
		want []string
	}{
		{"prefix only", map[string]any{"prefix": "NUXT_"}, []string{"NUXT_A", "NUXT_B"}},
		{"secrets allowlist", map[string]any{"secrets": []any{"DB_URL"}}, []string{"DB_URL"}},
		{"union of secrets+prefix", map[string]any{"secrets": []any{"DB_URL"}, "prefix": "NUXT_"}, []string{"DB_URL", "NUXT_A", "NUXT_B"}},
		{"no filter injects all four", map[string]any{}, []string{"API_KEY", "DB_URL", "NUXT_A", "NUXT_B"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := run(c.args)
			if strings.Join(got, " ") != strings.Join(c.want, " ") {
				t.Errorf("injected names = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRunWithSecretsScrubsTinyVaultControlCredentials(t *testing.T) {
	t.Setenv("TVAULT_PASSPHRASE", "must-not-leak")
	t.Setenv("TVAULT_IDENTITY_KEY", "must-not-leak")
	t.Setenv("TVAULT_AGENT_TOKEN", "must-not-leak")

	srv, v := newScratchServer(t)
	if err := v.SetSecret("default", "TVAULT_PASSPHRASE", "also-reserved"); err != nil {
		t.Fatal(err)
	}
	_, out, err := srv.handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: `for k in TVAULT_PASSPHRASE TVAULT_IDENTITY_KEY TVAULT_AGENT_TOKEN; do printenv "$k" >/dev/null 2>&1 && echo "$k"; done`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.Stdout) != "" {
		t.Fatalf("control credential names reached child environment: %q", out.Stdout)
	}
}

func TestRunWithSecretsAppliesSecretPolicy(t *testing.T) {
	srv, _ := newScratchServer(t)
	srv.policy.SecretsAllow = []string{"DB_*"}

	_, out, err := srv.handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: `for k in DB_URL API_KEY; do printenv "$k" >/dev/null 2>&1 && echo "$k"; done`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.Stdout); got != "DB_URL" {
		t.Fatalf("policy-filtered child environment = %q, want DB_URL", got)
	}

	if _, _, err := srv.handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: "true",
		Secrets: []string{"API_KEY"},
	}); err == nil {
		t.Fatal("explicitly requested denied secret was accepted")
	}
}
