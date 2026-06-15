package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// newScratchServer creates a freshly-initialized vault in a temp dir, seeds it
// with a couple of secrets, and returns a VaultMCPServer wired to a permissive
// policy. The vault is closed automatically when the test finishes.
func newScratchServer(t *testing.T) (*VaultMCPServer, *vault.Vault) {
	t.Helper()

	dir := t.TempDir()
	v, err := vault.Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() {
		if cerr := v.Close(); cerr != nil {
			t.Errorf("close vault: %v", cerr)
		}
	})

	if err := v.SetSecret("default", "DB_URL", "postgres://localhost/test"); err != nil {
		t.Fatalf("set DB_URL: %v", err)
	}
	if err := v.SetSecret("default", "API_KEY", "sk-secret-value-123"); err != nil {
		t.Fatalf("set API_KEY: %v", err)
	}

	return NewVaultMCPServer(v, DefaultPolicy()), v
}

func TestLoadPolicy_ParsesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yml")
	content := `access_mode: read-only
projects_allow:
  - "staging-*"
projects_deny:
  - "production-*"
secrets_allow:
  - "*"
secrets_deny:
  - "*_PRIVATE_KEY"
allow_exec: false
max_reads_per_session: 10
redact_output: true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p == nil {
		t.Fatal("LoadPolicy returned nil policy")
	}
	if p.AccessMode != "read-only" {
		t.Errorf("AccessMode = %q, want %q", p.AccessMode, "read-only")
	}
	if p.MaxReadsPerSession != 10 {
		t.Errorf("MaxReadsPerSession = %d, want 10", p.MaxReadsPerSession)
	}
	if p.AllowExec {
		t.Error("AllowExec should be false")
	}
	if !p.RedactOutput {
		t.Error("RedactOutput should be true")
	}

	// Allow/deny matching via the parsed policy.
	if !p.CanAccessProject("staging-api") {
		t.Error("staging-api should be allowed")
	}
	if p.CanAccessProject("production-main") {
		t.Error("production-main should be denied")
	}
	if !p.CanAccessSecret("DATABASE_URL") {
		t.Error("DATABASE_URL should be allowed")
	}
	if p.CanAccessSecret("SSH_PRIVATE_KEY") {
		t.Error("SSH_PRIVATE_KEY should be denied")
	}
	// read-only mode forbids writes and exec.
	if p.CanWrite() {
		t.Error("read-only policy should not allow writes")
	}
	if p.CanExec() {
		t.Error("read-only policy should not allow exec")
	}
}

func TestLoadPolicy_MissingFileReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yml")
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy on missing file returned error: %v", err)
	}
	if p != nil {
		t.Errorf("expected nil policy for missing file, got %+v", p)
	}
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(path, []byte("access_mode: [unterminated\n"), 0o600); err != nil {
		t.Fatalf("write bad policy: %v", err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestHandleExportEnv_WritesFileNoValues(t *testing.T) {
	srv, _ := newScratchServer(t)

	outPath := filepath.Join(t.TempDir(), "exported.env")
	_, out, err := srv.handleExportEnv(context.Background(), nil, exportEnvInput{
		Project:    "default",
		Format:     "dotenv",
		OutputPath: outPath,
	})
	if err != nil {
		t.Fatalf("handleExportEnv: %v", err)
	}

	if out.Path != outPath {
		t.Errorf("Path = %q, want %q", out.Path, outPath)
	}
	if out.Count != 2 {
		t.Errorf("Count = %d, want 2", out.Count)
	}

	// The response (path + key names) must never carry raw secret values.
	respJSON, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	for _, secret := range []string{"postgres://localhost/test", "sk-secret-value-123"} {
		if strings.Contains(string(respJSON), secret) {
			t.Errorf("export response leaked a secret value: %s", respJSON)
		}
	}

	// The file on disk should contain the values (it is the intended sink).
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if !strings.Contains(string(data), "postgres://localhost/test") {
		t.Error("exported file should contain the DB_URL value")
	}
	if !strings.Contains(string(data), "DB_URL") || !strings.Contains(string(data), "API_KEY") {
		t.Error("exported file should contain both keys")
	}
}

func TestHandleExportEnv_FormatsAndKeyFilter(t *testing.T) {
	srv, _ := newScratchServer(t)

	dir := t.TempDir()
	cases := []struct {
		format string
		out    string
	}{
		{"json", filepath.Join(dir, "out.json")},
		{"shell", filepath.Join(dir, "out.sh")},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			_, out, err := srv.handleExportEnv(context.Background(), nil, exportEnvInput{
				Project:    "default",
				Format:     tc.format,
				OutputPath: tc.out,
				Keys:       []string{"DB_URL"},
			})
			if err != nil {
				t.Fatalf("handleExportEnv(%s): %v", tc.format, err)
			}
			if out.Count != 1 {
				t.Errorf("Count = %d, want 1 (key filter)", out.Count)
			}
			if len(out.Keys) != 1 || out.Keys[0] != "DB_URL" {
				t.Errorf("Keys = %v, want [DB_URL]", out.Keys)
			}
			data, err := os.ReadFile(tc.out)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			if !strings.Contains(string(data), "DB_URL") {
				t.Errorf("%s file missing DB_URL: %s", tc.format, data)
			}
			if strings.Contains(string(data), "sk-secret-value-123") {
				t.Error("key-filtered export leaked the unrelated API_KEY value")
			}
		})
	}
}

func TestHandleExportEnv_Errors(t *testing.T) {
	srv, _ := newScratchServer(t)
	ctx := context.Background()

	t.Run("missing key", func(t *testing.T) {
		if _, _, err := srv.handleExportEnv(ctx, nil, exportEnvInput{
			Project: "default",
			Keys:    []string{"NOPE"},
		}); err == nil {
			t.Error("expected error for missing key")
		}
	})

	t.Run("unsupported format", func(t *testing.T) {
		if _, _, err := srv.handleExportEnv(ctx, nil, exportEnvInput{
			Project:    "default",
			Format:     "xml",
			OutputPath: filepath.Join(t.TempDir(), "out.xml"),
		}); err == nil {
			t.Error("expected error for unsupported format")
		}
	})

	t.Run("project blocked by policy", func(t *testing.T) {
		restricted := NewVaultMCPServer(srv.vault, &AccessPolicy{
			AccessMode:    "full",
			ProjectsAllow: []string{"other"},
		})
		if _, _, err := restricted.handleExportEnv(ctx, nil, exportEnvInput{
			Project: "default",
		}); err == nil {
			t.Error("expected error for policy-blocked project")
		}
	})
}

func TestHandleInjectSecretsPrompt(t *testing.T) {
	srv, _ := newScratchServer(t)
	ctx := context.Background()

	t.Run("with project", func(t *testing.T) {
		req := &sdkmcp.GetPromptRequest{
			Params: &sdkmcp.GetPromptParams{
				Arguments: map[string]string{"project": "default", "command": "go test ./..."},
			},
		}
		res, err := srv.handleInjectSecretsPrompt(ctx, req)
		if err != nil {
			t.Fatalf("handleInjectSecretsPrompt: %v", err)
		}
		if len(res.Messages) != 1 {
			t.Fatalf("expected 1 message, got %d", len(res.Messages))
		}
		text := res.Messages[0].Content.(*sdkmcp.TextContent).Text
		if !strings.Contains(text, "go test ./...") {
			t.Error("prompt should mention the command")
		}
		if !strings.Contains(text, `"default"`) {
			t.Error("prompt should mention the project clause")
		}
		if !strings.Contains(res.Description, "default") {
			t.Errorf("description should mention project: %q", res.Description)
		}
		// No raw secret values in the prompt.
		for _, secret := range []string{"postgres://localhost/test", "sk-secret-value-123"} {
			if strings.Contains(text, secret) {
				t.Errorf("prompt leaked a secret value: %s", text)
			}
		}
	})

	t.Run("default project clause", func(t *testing.T) {
		req := &sdkmcp.GetPromptRequest{
			Params: &sdkmcp.GetPromptParams{
				Arguments: map[string]string{"command": "npm start"},
			},
		}
		res, err := srv.handleInjectSecretsPrompt(ctx, req)
		if err != nil {
			t.Fatalf("handleInjectSecretsPrompt: %v", err)
		}
		text := res.Messages[0].Content.(*sdkmcp.TextContent).Text
		if !strings.Contains(text, "the current project") {
			t.Error("prompt should fall back to 'the current project'")
		}
	})

	t.Run("missing command errors", func(t *testing.T) {
		req := &sdkmcp.GetPromptRequest{
			Params: &sdkmcp.GetPromptParams{Arguments: map[string]string{}},
		}
		if _, err := srv.handleInjectSecretsPrompt(ctx, req); err == nil {
			t.Error("expected error for missing command")
		}
	})
}

func TestRandomFromCharset(t *testing.T) {
	const charset = "ABCDEF0123456789"
	const length = 40

	first, err := randomFromCharset(length, charset)
	if err != nil {
		t.Fatalf("randomFromCharset: %v", err)
	}
	if len(first) != length {
		t.Errorf("len = %d, want %d", len(first), length)
	}
	for _, c := range first {
		if !strings.ContainsRune(charset, c) {
			t.Errorf("char %q not in charset", c)
		}
	}

	// Two successive calls should differ (probabilistically certain at len 40).
	second, err := randomFromCharset(length, charset)
	if err != nil {
		t.Fatalf("randomFromCharset (second): %v", err)
	}
	if first == second {
		t.Error("two random outputs should differ")
	}
}

func TestRandomFromCharset_Empty(t *testing.T) {
	out, err := randomFromCharset(0, "abc")
	if err != nil {
		t.Fatalf("randomFromCharset(0): %v", err)
	}
	if out != "" {
		t.Errorf("expected empty string, got %q", out)
	}
}
