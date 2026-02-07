package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.AccessMode != "full" {
		t.Errorf("AccessMode = %q, want %q", p.AccessMode, "full")
	}
	if !p.AllowExec {
		t.Error("AllowExec should be true by default")
	}
	if !p.RedactOutput {
		t.Error("RedactOutput should be true by default")
	}
	if p.MaxReadsPerSession != 50 {
		t.Errorf("MaxReadsPerSession = %d, want 50", p.MaxReadsPerSession)
	}
	if !p.CanWrite() {
		t.Error("full mode should allow writes")
	}
	if !p.CanExec() {
		t.Error("full mode with AllowExec should allow exec")
	}
}

func TestPolicyCanAccessProject_AllowDeny(t *testing.T) {
	tests := []struct {
		name     string
		policy   AccessPolicy
		project  string
		expected bool
	}{
		{
			name:     "allow all",
			policy:   AccessPolicy{ProjectsAllow: []string{"*"}},
			project:  "anything",
			expected: true,
		},
		{
			name:     "allow specific",
			policy:   AccessPolicy{ProjectsAllow: []string{"myapp"}},
			project:  "myapp",
			expected: true,
		},
		{
			name:     "deny specific",
			policy:   AccessPolicy{ProjectsAllow: []string{"*"}, ProjectsDeny: []string{"production-*"}},
			project:  "production-main",
			expected: false,
		},
		{
			name:     "deny takes precedence over allow",
			policy:   AccessPolicy{ProjectsAllow: []string{"production-*"}, ProjectsDeny: []string{"production-*"}},
			project:  "production-main",
			expected: false,
		},
		{
			name:     "not in allow list",
			policy:   AccessPolicy{ProjectsAllow: []string{"myapp"}},
			project:  "other",
			expected: false,
		},
		{
			name:     "empty allow list allows all",
			policy:   AccessPolicy{ProjectsAllow: nil},
			project:  "anything",
			expected: true,
		},
		{
			name:     "glob match",
			policy:   AccessPolicy{ProjectsAllow: []string{"staging-*"}},
			project:  "staging-api",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.CanAccessProject(tt.project)
			if got != tt.expected {
				t.Errorf("CanAccessProject(%q) = %v, want %v", tt.project, got, tt.expected)
			}
		})
	}
}

func TestPolicyCanAccessSecret_AllowDeny(t *testing.T) {
	tests := []struct {
		name     string
		policy   AccessPolicy
		key      string
		expected bool
	}{
		{
			name:     "allow all",
			policy:   AccessPolicy{SecretsAllow: []string{"*"}},
			key:      "DATABASE_URL",
			expected: true,
		},
		{
			name:     "deny pattern",
			policy:   AccessPolicy{SecretsAllow: []string{"*"}, SecretsDeny: []string{"*_PRIVATE_KEY"}},
			key:      "SSH_PRIVATE_KEY",
			expected: false,
		},
		{
			name:     "allow specific",
			policy:   AccessPolicy{SecretsAllow: []string{"API_KEY"}},
			key:      "API_KEY",
			expected: true,
		},
		{
			name:     "not in allow",
			policy:   AccessPolicy{SecretsAllow: []string{"API_KEY"}},
			key:      "DATABASE_URL",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.CanAccessSecret(tt.key)
			if got != tt.expected {
				t.Errorf("CanAccessSecret(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}

func TestPolicyCanWrite(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"read-only", false},
		{"read-write", true},
		{"full", true},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			p := &AccessPolicy{AccessMode: tt.mode}
			if got := p.CanWrite(); got != tt.want {
				t.Errorf("CanWrite() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyCanExec(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		allowExec bool
		want      bool
	}{
		{"full with exec", "full", true, true},
		{"full without exec", "full", false, false},
		{"read-write with exec", "read-write", true, false},
		{"read-only with exec", "read-only", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &AccessPolicy{AccessMode: tt.mode, AllowExec: tt.allowExec}
			if got := p.CanExec(); got != tt.want {
				t.Errorf("CanExec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRedactSecrets(t *testing.T) {
	secrets := map[string]string{
		"DATABASE_URL": "postgres://user:pass@host:5432/db",
		"API_KEY":      "sk-abc123xyz",
	}
	output := "Connected to postgres://user:pass@host:5432/db using key sk-abc123xyz"

	result := redactSecrets(output, secrets)

	if result == output {
		t.Error("expected output to be redacted")
	}
	expected := "Connected to [REDACTED:DATABASE_URL] using key [REDACTED:API_KEY]"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestRedactSecrets_ShortValues(t *testing.T) {
	secrets := map[string]string{
		"SHORT": "ab",
		"EXACT": "abc",
		"LONG":  "abcd",
	}
	output := "values: ab abc abcd"

	result := redactSecrets(output, secrets)

	// "ab" (2 chars) and "abc" (3 chars) should NOT be redacted
	// "abcd" (4 chars) should be redacted
	expected := "values: ab abc [REDACTED:LONG]"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

// TestMCPServerIntegration tests tool registration and calls via in-memory transport.
func TestMCPServerIntegration(t *testing.T) {
	dir := t.TempDir()
	v, err := vault.Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer v.Close()

	if err := v.SetSecret("default", "DB_URL", "postgres://localhost/test"); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	if err := v.SetSecret("default", "API_KEY", "sk-test-key-12345"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	policy := DefaultPolicy()
	srv := NewVaultMCPServer(v, policy)

	ctx := context.Background()
	t1, t2 := sdkmcp.NewInMemoryTransports()

	_, err = srv.server.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	t.Run("list_tools", func(t *testing.T) {
		tools := make([]*sdkmcp.Tool, 0, 8)
		for tool, err := range cs.Tools(ctx, nil) {
			if err != nil {
				t.Fatalf("list tools: %v", err)
			}
			tools = append(tools, tool)
		}
		// We expect 6 tools: list_projects, list_secrets, get_secret, set_secret, delete_secret, run_with_secrets, export_env
		if len(tools) < 6 {
			t.Errorf("expected at least 6 tools, got %d", len(tools))
		}
		toolNames := make(map[string]bool)
		for _, tool := range tools {
			toolNames[tool.Name] = true
		}
		for _, name := range []string{
			"vault_list_projects",
			"vault_list_secrets",
			"vault_get_secret",
			"vault_set_secret",
			"vault_delete_secret",
			"vault_run_with_secrets",
			"vault_export_env",
		} {
			if !toolNames[name] {
				t.Errorf("missing tool: %s", name)
			}
		}
	})

	t.Run("vault_list_projects", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_list_projects",
		})
		if err != nil {
			t.Fatalf("call vault_list_projects: %v", err)
		}
		if res.IsError {
			t.Fatalf("tool returned error")
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out listProjectsOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out.Projects) != 1 {
			t.Fatalf("expected 1 project, got %d", len(out.Projects))
		}
		if out.Projects[0].Name != "default" {
			t.Errorf("project name = %q, want %q", out.Projects[0].Name, "default")
		}
		if out.Projects[0].SecretCount != 2 {
			t.Errorf("secret count = %d, want 2", out.Projects[0].SecretCount)
		}
	})

	t.Run("vault_list_secrets", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_list_secrets",
			Arguments: map[string]any{"project": "default"},
		})
		if err != nil {
			t.Fatalf("call vault_list_secrets: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out listSecretsOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out.Secrets) != 2 {
			t.Fatalf("expected 2 secrets, got %d", len(out.Secrets))
		}
		// Verify no values are returned
		for _, s := range out.Secrets {
			if s.Key == "" {
				t.Error("secret key should not be empty")
			}
		}
	})

	t.Run("vault_get_secret", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_get_secret",
			Arguments: map[string]any{"key": "DB_URL"},
		})
		if err != nil {
			t.Fatalf("call vault_get_secret: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out getSecretOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.Value != "postgres://localhost/test" {
			t.Errorf("value = %q, want %q", out.Value, "postgres://localhost/test")
		}
		if out.Warning == "" {
			t.Error("expected warning about AI context exposure")
		}
	})

	t.Run("vault_set_secret", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_set_secret",
			Arguments: map[string]any{"key": "NEW_KEY", "value": "new-value"},
		})
		if err != nil {
			t.Fatalf("call vault_set_secret: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out setSecretOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.Key != "NEW_KEY" {
			t.Errorf("key = %q, want %q", out.Key, "NEW_KEY")
		}

		// Verify it was actually stored
		val, err := v.GetSecret("default", "NEW_KEY")
		if err != nil {
			t.Fatalf("verify set: %v", err)
		}
		if val != "new-value" {
			t.Errorf("stored value = %q, want %q", val, "new-value")
		}
	})

	t.Run("vault_delete_secret", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_delete_secret",
			Arguments: map[string]any{"key": "NEW_KEY"},
		})
		if err != nil {
			t.Fatalf("call vault_delete_secret: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out deleteSecretOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !out.Deleted {
			t.Error("expected deleted to be true")
		}
	})

	t.Run("vault_run_with_secrets", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_run_with_secrets",
			Arguments: map[string]any{
				"command": "echo DB is $DB_URL",
			},
		})
		if err != nil {
			t.Fatalf("call vault_run_with_secrets: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out runResult
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.ExitCode != 0 {
			t.Errorf("exit code = %d, want 0", out.ExitCode)
		}
		// The output should have the DB_URL value redacted
		if out.Stdout == "" {
			t.Error("expected non-empty stdout")
		}
		if out.Stdout != "DB is [REDACTED:DB_URL]\n" {
			t.Errorf("stdout = %q, expected redacted output", out.Stdout)
		}
	})

	t.Run("policy_read_only_blocks_writes", func(t *testing.T) {
		// Create a read-only server
		roPolicy := &AccessPolicy{
			AccessMode:    "read-only",
			ProjectsAllow: []string{"*"},
			SecretsAllow:  []string{"*"},
		}
		roSrv := NewVaultMCPServer(v, roPolicy)

		rt1, rt2 := sdkmcp.NewInMemoryTransports()
		_, err = roSrv.server.Connect(ctx, rt1, nil)
		if err != nil {
			t.Fatalf("server connect: %v", err)
		}
		roClient := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "ro-client", Version: "v0.0.1"}, nil)
		roCs, err := roClient.Connect(ctx, rt2, nil)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		defer roCs.Close()

		res, err := roCs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_set_secret",
			Arguments: map[string]any{"key": "BLOCKED", "value": "nope"},
		})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !res.IsError {
			t.Error("expected error for write in read-only mode")
		}
	})
}
