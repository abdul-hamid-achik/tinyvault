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
	// We use a for-loop + test -n rather than printenv | grep to avoid
	// grep emitting ANSI color codes when GREP_COLORS is set in the
	// environment (macOS default in some shells).
	const listNames = `for k in NUXT_A NUXT_B DB_URL API_KEY; do if [ -n "${!k}" ]; then echo "$k"; fi; done | sort`

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
