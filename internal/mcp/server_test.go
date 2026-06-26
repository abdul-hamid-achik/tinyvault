package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
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

	envDir := t.TempDir()
	for name, content := range map[string]string{
		".env":                  "IMPORT_API=base-value\nSHARED_KEY=base-shared\nBLOCKED_KEY=blocked-base\n",
		".env.production":       "SHARED_KEY=prod-shared\n",
		".env.local":            "LOCAL_ONLY=local-value\n",
		".env.production.local": "IMPORT_API=prod-local\n",
		"secrets.env":           "UNSAFE_FILE=should-not-import\n",
	} {
		if err := os.WriteFile(filepath.Join(envDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
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
		tools := make([]*sdkmcp.Tool, 0, 16)
		for tool, err := range cs.Tools(ctx, nil) {
			if err != nil {
				t.Fatalf("list tools: %v", err)
			}
			tools = append(tools, tool)
		}
		if len(tools) != 49 {
			t.Errorf("expected 49 tools, got %d", len(tools))
		}
		toolNames := make(map[string]bool)
		for _, tool := range tools {
			toolNames[tool.Name] = true
		}
		for _, name := range []string{
			"vault_list_projects",
			"vault_create_project",
			"vault_delete_project",
			"vault_list_secrets",
			"vault_get_secret",
			"vault_set_secret",
			"vault_delete_secret",
			"vault_run_with_secrets",
			"vault_export_env",
			"vault_list_env_files",
			"vault_preview_env_import",
			"vault_import_env_files",
			"vault_status",
			"vault_audit_log",
			"vault_generate_secret",
			"vault_search_secrets",
			"vault_list_secrets_by_prefix",
			"vault_audit_log_since",
			"vault_seal_for_recipients",
			"vault_secret_history",
			"vault_rollback_secret",
			"vault_get_current_project",
			"vault_set_current_project",
			"vault_count_secrets",
			"vault_search_projects",
			"vault_projects_overview",
			"vault_list_secrets_detailed",
			"vault_list_secrets_global",
			"vault_share_project",
			"vault_unshare_project",
			"vault_project_recipients",
			"vault_diff_env",
			"vault_sync_env",
			"vault_export_env_encrypted",
			"vault_identity_new",
			"vault_identity_list",
			"vault_env_group_create",
			"vault_env_group_list",
			"vault_env_diff",
			"vault_env_promote",
			"vault_env_seal",
			"vault_env_inherit",
			"vault_env_inherited",
			"vault_env_group_show",
			"vault_env_group_add",
			"vault_env_group_remove",
			"vault_env_group_delete",
			"vault_env_pin",
			"vault_env_unpin",
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

	t.Run("vault_list_env_files", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_list_env_files",
			Arguments: map[string]any{"directory": envDir, "environment": "production"},
		})
		if err != nil {
			t.Fatalf("call vault_list_env_files: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out listEnvFilesOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out.Files) != 4 {
			t.Fatalf("expected 4 dotenv files, got %d", len(out.Files))
		}
		if len(out.SuggestedFiles) != 4 {
			t.Fatalf("expected 4 suggested files, got %d", len(out.SuggestedFiles))
		}
	})

	t.Run("vault_preview_env_import", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_preview_env_import",
			Arguments: map[string]any{
				"directory":   envDir,
				"environment": "production",
				"overwrite":   true,
			},
		})
		if err != nil {
			t.Fatalf("call vault_preview_env_import: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out previewEnvImportOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.Project != "default" {
			t.Fatalf("project = %q, want %q", out.Project, "default")
		}
		if out.CreateCount != 4 {
			t.Fatalf("CreateCount = %d, want 4", out.CreateCount)
		}
		if out.OverwriteCount != 0 {
			t.Fatalf("OverwriteCount = %d, want 0", out.OverwriteCount)
		}
		if strings.Contains(text, "prod-local") || strings.Contains(text, "base-value") {
			t.Fatal("preview output leaked a secret value")
		}
	})

	t.Run("vault_preview_env_import_rejects_unsafe_explicit_file", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_preview_env_import",
			Arguments: map[string]any{
				"files": []string{filepath.Join(envDir, "secrets.env")},
			},
		})
		if err != nil {
			t.Fatalf("call vault_preview_env_import: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected unsafe explicit file preview to fail")
		}
	})

	t.Run("vault_preview_env_import_rejects_explicit_file_outside_directory", func(t *testing.T) {
		otherDir := t.TempDir()
		otherFile := filepath.Join(otherDir, ".env")
		if err := os.WriteFile(otherFile, []byte("OUTSIDE_DIR=blocked\n"), 0o600); err != nil {
			t.Fatalf("write outside dotenv file: %v", err)
		}

		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_preview_env_import",
			Arguments: map[string]any{
				"directory": envDir,
				"files":     []string{otherFile},
			},
		})
		if err != nil {
			t.Fatalf("call vault_preview_env_import: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected explicit file outside directory to fail")
		}
	})

	t.Run("vault_import_env_files", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_import_env_files",
			Arguments: map[string]any{
				"directory":   envDir,
				"environment": "production",
				"overwrite":   true,
			},
		})
		if err != nil {
			t.Fatalf("call vault_import_env_files: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out importEnvFilesOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.CreateCount != 4 {
			t.Fatalf("CreateCount = %d, want 4", out.CreateCount)
		}
		if strings.Contains(text, "prod-local") || strings.Contains(text, "base-value") {
			t.Fatal("import output leaked a secret value")
		}

		val, err := v.GetSecret("default", "IMPORT_API")
		if err != nil {
			t.Fatalf("verify IMPORT_API: %v", err)
		}
		if val != "prod-local" {
			t.Fatalf("IMPORT_API = %q, want %q", val, "prod-local")
		}

		val, err = v.GetSecret("default", "SHARED_KEY")
		if err != nil {
			t.Fatalf("verify SHARED_KEY: %v", err)
		}
		if val != "prod-shared" {
			t.Fatalf("SHARED_KEY = %q, want %q", val, "prod-shared")
		}
	})

	t.Run("vault_create_project", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_create_project",
			Arguments: map[string]any{"name": "test-proj", "description": "A test project"},
		})
		if err != nil {
			t.Fatalf("call vault_create_project: %v", err)
		}
		if res.IsError {
			text := res.Content[0].(*sdkmcp.TextContent).Text
			t.Fatalf("tool returned error: %s", text)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out createProjectOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !out.Created {
			t.Error("expected created to be true")
		}
		if out.Name != "test-proj" {
			t.Errorf("name = %q, want %q", out.Name, "test-proj")
		}
	})

	t.Run("vault_delete_project", func(t *testing.T) {
		// First create a project to delete
		_, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_create_project",
			Arguments: map[string]any{"name": "to-delete"},
		})
		if err != nil {
			t.Fatalf("create project: %v", err)
		}

		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_delete_project",
			Arguments: map[string]any{"name": "to-delete"},
		})
		if err != nil {
			t.Fatalf("call vault_delete_project: %v", err)
		}
		if res.IsError {
			text := res.Content[0].(*sdkmcp.TextContent).Text
			t.Fatalf("tool returned error: %s", text)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out deleteProjectOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !out.Deleted {
			t.Error("expected deleted to be true")
		}
	})

	t.Run("vault_status", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_status",
		})
		if err != nil {
			t.Fatalf("call vault_status: %v", err)
		}
		if res.IsError {
			text := res.Content[0].(*sdkmcp.TextContent).Text
			t.Fatalf("tool returned error: %s", text)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out vaultStatusOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !out.IsUnlocked {
			t.Error("expected vault to be unlocked")
		}
		if out.ProjectCount < 1 {
			t.Errorf("expected at least 1 project, got %d", out.ProjectCount)
		}
		if out.VaultID == "" {
			t.Error("expected non-empty vault ID")
		}
	})

	t.Run("vault_generate_secret", func(t *testing.T) {
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_generate_secret",
			Arguments: map[string]any{
				"key":     "GENERATED_TOKEN",
				"length":  float64(24),
				"charset": "hex",
			},
		})
		if err != nil {
			t.Fatalf("call vault_generate_secret: %v", err)
		}
		if res.IsError {
			text := res.Content[0].(*sdkmcp.TextContent).Text
			t.Fatalf("tool returned error: %s", text)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out generateSecretOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !out.Stored {
			t.Error("expected stored to be true")
		}
		if out.Key != "GENERATED_TOKEN" {
			t.Errorf("key = %q, want %q", out.Key, "GENERATED_TOKEN")
		}
		if out.Length != 24 {
			t.Errorf("length = %d, want 24", out.Length)
		}
		// Verify the value is NOT in the output
		if text != "" {
			var raw map[string]any
			_ = json.Unmarshal([]byte(text), &raw)
			if _, hasValue := raw["value"]; hasValue {
				t.Error("generated value should NOT be returned to the AI")
			}
		}
		// Verify it was actually stored
		val, err := v.GetSecret("default", "GENERATED_TOKEN")
		if err != nil {
			t.Fatalf("verify generated: %v", err)
		}
		if len(val) != 24 {
			t.Errorf("generated value length = %d, want 24", len(val))
		}
	})

	t.Run("vault_audit_log", func(t *testing.T) {
		// The previous operations should have created audit entries
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_audit_log",
			Arguments: map[string]any{"limit": float64(50)},
		})
		if err != nil {
			t.Fatalf("call vault_audit_log: %v", err)
		}
		if res.IsError {
			text := res.Content[0].(*sdkmcp.TextContent).Text
			t.Fatalf("tool returned error: %s", text)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out auditLogOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out.Entries) == 0 {
			t.Error("expected at least one audit entry from previous operations")
		}
		// Look for known actions
		actions := make(map[string]bool)
		for _, e := range out.Entries {
			actions[e.Action] = true
		}
		for _, expected := range []string{"secret.read", "secret.write", "secret.delete", "project.create", "env.import"} {
			if !actions[expected] {
				t.Errorf("missing audit action: %s (found: %v)", expected, actions)
			}
		}
	})

	t.Run("vault_search_secrets", func(t *testing.T) {
		// Add a uniquely-named secret so we can search for it.
		if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_set_secret",
			Arguments: map[string]any{"key": "UNIQUE_SEARCH_TOKEN", "value": "x"},
		}); err != nil {
			t.Fatalf("set UNIQUE_SEARCH_TOKEN: %v", err)
		}

		// Search by exact name pattern.
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_search_secrets",
			Arguments: map[string]any{"name_like": "UNIQUE_SEARCH_*"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.IsError {
			text := res.Content[0].(*sdkmcp.TextContent).Text
			t.Fatalf("search returned error: %s", text)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out searchSecretsOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v\nbody: %s", err, text)
		}
		if out.Count != 1 {
			t.Errorf("expected count=1, got %d (results: %+v)", out.Count, out.Results)
		}
		if len(out.Results) > 0 && out.Results[0].Key != "UNIQUE_SEARCH_TOKEN" {
			t.Errorf("expected UNIQUE_SEARCH_TOKEN, got %+v", out.Results[0])
		}
	})

	t.Run("vault_list_secrets_by_prefix", func(t *testing.T) {
		// Use a prefix that no other test uses.
		prefix := "PFX_" + uniqueSuffix()
		if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_set_secret",
			Arguments: map[string]any{"key": prefix + "_A", "value": "a"},
		}); err != nil {
			t.Fatalf("set PFX_A: %v", err)
		}
		if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_set_secret",
			Arguments: map[string]any{"key": prefix + "_B", "value": "b"},
		}); err != nil {
			t.Fatalf("set PFX_B: %v", err)
		}
		if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_set_secret",
			Arguments: map[string]any{"key": "OTHER_KEY", "value": "x"},
		}); err != nil {
			t.Fatalf("set OTHER_KEY: %v", err)
		}

		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_list_secrets_by_prefix",
			Arguments: map[string]any{"prefix": prefix},
		})
		if err != nil {
			t.Fatalf("list by prefix: %v", err)
		}
		if res.IsError {
			text := res.Content[0].(*sdkmcp.TextContent).Text
			t.Fatalf("tool error: %s", text)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out listByPrefixOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out.Keys) != 2 {
			t.Errorf("expected 2 PFX_* keys, got %d: %v", len(out.Keys), out.Keys)
		}
		for _, k := range out.Keys {
			if !strings.HasPrefix(k, prefix) {
				t.Errorf("key %q does not start with %q", k, prefix)
			}
		}
	})

	t.Run("vault_audit_log_since", func(t *testing.T) {
		// Filter by action=secret.read; we should get audit entries.
		res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_audit_log_since",
			Arguments: map[string]any{"action": "secret.read", "limit": float64(10)},
		})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if res.IsError {
			text := res.Content[0].(*sdkmcp.TextContent).Text
			t.Fatalf("tool error: %s", text)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out auditLogOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out.Entries) == 0 {
			t.Error("expected at least one secret.read entry")
		}
		for _, e := range out.Entries {
			if e.Action != "secret.read" {
				t.Errorf("action filter leaked: got %q", e.Action)
			}
		}
	})

	t.Run("resource_vault_status", func(t *testing.T) {
		res, err := cs.ReadResource(ctx, &sdkmcp.ReadResourceParams{URI: "vault://status"})
		if err != nil {
			t.Fatalf("read resource: %v", err)
		}
		if len(res.Contents) != 1 {
			t.Fatalf("expected 1 content, got %d", len(res.Contents))
		}
		var status vaultStatusOutput
		if err := json.Unmarshal([]byte(res.Contents[0].Text), &status); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !status.IsUnlocked {
			t.Error("expected vault unlocked")
		}
	})

	t.Run("resource_vault_projects", func(t *testing.T) {
		res, err := cs.ReadResource(ctx, &sdkmcp.ReadResourceParams{URI: "vault://projects"})
		if err != nil {
			t.Fatalf("read resource: %v", err)
		}
		if len(res.Contents) != 1 {
			t.Fatalf("expected 1 content, got %d", len(res.Contents))
		}
		var projects []projectInfo
		if err := json.Unmarshal([]byte(res.Contents[0].Text), &projects); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(projects) < 1 {
			t.Error("expected at least 1 project")
		}
	})

	t.Run("resource_project_keys", func(t *testing.T) {
		res, err := cs.ReadResource(ctx, &sdkmcp.ReadResourceParams{URI: "vault://projects/default/keys"})
		if err != nil {
			t.Fatalf("read resource: %v", err)
		}
		if len(res.Contents) != 1 {
			t.Fatalf("expected 1 content, got %d", len(res.Contents))
		}
		var keys []string
		if err := json.Unmarshal([]byte(res.Contents[0].Text), &keys); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(keys) < 2 {
			t.Errorf("expected at least 2 keys, got %d", len(keys))
		}
	})

	t.Run("list_prompts", func(t *testing.T) {
		prompts := make([]*sdkmcp.Prompt, 0, 4)
		for p, err := range cs.Prompts(ctx, nil) {
			if err != nil {
				t.Fatalf("list prompts: %v", err)
			}
			prompts = append(prompts, p)
		}
		if len(prompts) != 2 {
			t.Errorf("expected 2 prompts, got %d", len(prompts))
		}
		promptNames := make(map[string]bool)
		for _, p := range prompts {
			promptNames[p.Name] = true
		}
		for _, name := range []string{"setup-project", "inject-secrets"} {
			if !promptNames[name] {
				t.Errorf("missing prompt: %s", name)
			}
		}
	})

	t.Run("get_prompt_setup_project", func(t *testing.T) {
		res, err := cs.GetPrompt(ctx, &sdkmcp.GetPromptParams{
			Name:      "setup-project",
			Arguments: map[string]string{"name": "myapp"},
		})
		if err != nil {
			t.Fatalf("get prompt: %v", err)
		}
		if len(res.Messages) != 1 {
			t.Fatalf("expected 1 message, got %d", len(res.Messages))
		}
		text := res.Messages[0].Content.(*sdkmcp.TextContent).Text
		if text == "" {
			t.Error("expected non-empty prompt text")
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

		// Test set_secret blocked
		res, err := roCs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_set_secret",
			Arguments: map[string]any{"key": "BLOCKED", "value": "nope"},
		})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !res.IsError {
			t.Error("expected error for set_secret in read-only mode")
		}

		// Test create_project blocked
		res, err = roCs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_create_project",
			Arguments: map[string]any{"name": "blocked-proj"},
		})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !res.IsError {
			t.Error("expected error for create_project in read-only mode")
		}

		// Test delete_project blocked
		res, err = roCs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_delete_project",
			Arguments: map[string]any{"name": "default"},
		})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !res.IsError {
			t.Error("expected error for delete_project in read-only mode")
		}

		// Test generate_secret blocked
		res, err = roCs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name:      "vault_generate_secret",
			Arguments: map[string]any{"key": "BLOCKED_GEN"},
		})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !res.IsError {
			t.Error("expected error for generate_secret in read-only mode")
		}

		// Test dotenv import blocked
		res, err = roCs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_import_env_files",
			Arguments: map[string]any{
				"directory":   envDir,
				"environment": "production",
			},
		})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !res.IsError {
			t.Error("expected error for vault_import_env_files in read-only mode")
		}

		// Test vault_status is always allowed (even read-only)
		res, err = roCs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_status",
		})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if res.IsError {
			t.Error("vault_status should be allowed in read-only mode")
		}
	})

	t.Run("policy_filters_env_import_keys", func(t *testing.T) {
		restrictedPolicy := &AccessPolicy{
			AccessMode:    "full",
			ProjectsAllow: []string{"*"},
			SecretsAllow:  []string{"IMPORT_*"},
			AllowExec:     true,
		}
		restrictedSrv := NewVaultMCPServer(v, restrictedPolicy)

		rt1, rt2 := sdkmcp.NewInMemoryTransports()
		_, err = restrictedSrv.server.Connect(ctx, rt1, nil)
		if err != nil {
			t.Fatalf("server connect: %v", err)
		}
		restrictedClient := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "restricted-client", Version: "v0.0.1"}, nil)
		restrictedCs, err := restrictedClient.Connect(ctx, rt2, nil)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		defer restrictedCs.Close()

		res, err := restrictedCs.CallTool(ctx, &sdkmcp.CallToolParams{
			Name: "vault_preview_env_import",
			Arguments: map[string]any{
				"directory":   envDir,
				"environment": "production",
				"overwrite":   true,
			},
		})
		if err != nil {
			t.Fatalf("call vault_preview_env_import: %v", err)
		}
		text := res.Content[0].(*sdkmcp.TextContent).Text
		var out previewEnvImportOutput
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.BlockedCount != 3 {
			t.Fatalf("BlockedCount = %d, want 3", out.BlockedCount)
		}
		if len(out.Keys) != 1 || out.Keys[0].Key != "IMPORT_API" {
			t.Fatalf("allowed keys = %+v, want only IMPORT_API", out.Keys)
		}
	})
}

// uniqueSuffix returns a short, test-unique suffix based on the
// current nanosecond timestamp. Used by the relational-query tests
// to avoid name collisions with other subtests in the same
// integration suite.
func uniqueSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}
