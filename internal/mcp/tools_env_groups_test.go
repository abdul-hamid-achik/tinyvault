package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// setupEnvGroupTestVault creates a vault with two projects, secrets, a group,
// and an identity for seal tests. Returns the vault, server, client session,
// and the identity (for decrypt tests).
func setupEnvGroupTestVault(t *testing.T) (*vault.Vault, *VaultMCPServer, *sdkmcp.ClientSession, *crypto.Identity) {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Create(dir, "test-pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}

	// Create projects.
	if _, err := v.CreateProject("liftclub", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("liftclub-preview", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	// Set secrets.
	_ = v.SetSecret("liftclub", "DATABASE_URL", "prod-db")
	_ = v.SetSecret("liftclub", "STRIPE_SECRET_KEY", "sk-prod")
	_ = v.SetSecret("liftclub", "STRIPE_WEBHOOK_SECRET", "wh-prod")
	_ = v.SetSecret("liftclub-preview", "DATABASE_URL", "preview-db")
	_ = v.SetSecret("liftclub-preview", "STRIPE_SECRET_KEY", "sk-preview")
	// STRIPE_WEBHOOK_SECRET missing in preview → drift

	// Create group.
	_, _ = v.CreateEnvGroup("liftclub", "LIFT Club", []vault.EnvGroupEntry{
		{Name: "production", Project: "liftclub"},
		{Name: "preview", Project: "liftclub-preview"},
	}, false)

	// Create an identity for seal tests.
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	// Close the setup vault before reopening (bbolt is single-writer).
	v.Close()

	// Reopen the vault for the MCP server.
	v2, err := vault.Open(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := v2.Unlock("test-pass"); err != nil {
		t.Fatalf("unlock vault: %v", err)
	}

	policy := DefaultPolicy()
	srv := NewVaultMCPServer(v2, policy)

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
	t.Cleanup(func() {
		cs.Close()
		v2.Close()
	})

	return v2, srv, cs, identity
}

func callEnvTool(t *testing.T, ctx context.Context, cs *sdkmcp.ClientSession, name string, args map[string]any) []byte {
	t.Helper()
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("tool %s returned error: %s", name, res.Content[0].(*sdkmcp.TextContent).Text)
	}
	return []byte(res.Content[0].(*sdkmcp.TextContent).Text)
}

func TestMCPEnvGroupCreate(t *testing.T) {
	dir := t.TempDir()
	v, err := vault.Create(dir, "test-pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer v.Close()

	if _, err := v.CreateProject("app1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("app1-staging", ""); err != nil {
		t.Fatalf("create project: %v", err)
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

	data := callEnvTool(t, ctx, cs, "vault_env_group_create", map[string]any{
		"name":        "app1",
		"description": "App1 environments",
		"environments": []map[string]any{
			{"name": "production", "project": "app1"},
			{"name": "staging", "project": "app1-staging"},
		},
	})

	var out envGroupOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Name != "app1" {
		t.Errorf("name = %q, want %q", out.Name, "app1")
	}
	if len(out.Environments) != 2 {
		t.Fatalf("env count = %d, want 2", len(out.Environments))
	}
}

func TestMCPEnvGroupList(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	data := callEnvTool(t, ctx, cs, "vault_env_group_list", map[string]any{})

	var out envGroupListOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(out.Groups))
	}
	if out.Groups[0].Name != "liftclub" {
		t.Errorf("group name = %q, want %q", out.Groups[0].Name, "liftclub")
	}
}

func TestMCPEnvDiff(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	data := callEnvTool(t, ctx, cs, "vault_env_diff", map[string]any{
		"group": "liftclub",
	})

	var out envDiffOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Group != "liftclub" {
		t.Errorf("group = %q", out.Group)
	}
	if out.Status != "drift" {
		t.Errorf("status = %q, want %q", out.Status, "drift")
	}
	// STRIPE_WEBHOOK_SECRET should be missing in preview.
	found := false
	for _, k := range out.Keys {
		if k.Key == "STRIPE_WEBHOOK_SECRET" {
			found = true
			if k.Environments[1].Present {
				t.Error("STRIPE_WEBHOOK_SECRET should be missing in preview")
			}
		}
	}
	if !found {
		t.Error("STRIPE_WEBHOOK_SECRET not found in diff keys")
	}
}

func TestMCPEnvDiff_Values(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	data := callEnvTool(t, ctx, cs, "vault_env_diff", map[string]any{
		"group":  "liftclub",
		"values": true,
	})

	var out envDiffOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// DATABASE_URL should be "different" between envs.
	for _, k := range out.Keys {
		if k.Key == "DATABASE_URL" {
			for _, e := range k.Environments {
				if e.Status == "different" {
					return
				}
			}
		}
	}
	// If all DATABASE_URL entries are "same", that's wrong since they differ.
	t.Error("expected DATABASE_URL to have 'different' status")
}

func TestMCPEnvDiff_NoValuesReturned(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	data := callEnvTool(t, ctx, cs, "vault_env_diff", map[string]any{
		"group":  "liftclub",
		"values": true,
	})

	// Ensure no secret values appear in the output.
	text := string(data)
	if contains(text, "prod-db") || contains(text, "preview-db") || contains(text, "sk-prod") {
		t.Error("secret value found in diff output")
	}
}

func TestMCPEnvPromote(t *testing.T) {
	v, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	data := callEnvTool(t, ctx, cs, "vault_env_promote", map[string]any{
		"group":    "liftclub",
		"keys":     []string{"STRIPE_WEBHOOK_SECRET"},
		"from_env": "production",
		"to_env":   "preview",
	})

	var out envPromoteOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Promoted) != 1 {
		t.Fatalf("promoted = %d, want 1", len(out.Promoted))
	}
	if out.Promoted[0].Key != "STRIPE_WEBHOOK_SECRET" {
		t.Errorf("key = %q", out.Promoted[0].Key)
	}

	// Verify the value was promoted — no values returned in output, only versions.
	val, err := v.GetSecret("liftclub-preview", "STRIPE_WEBHOOK_SECRET")
	if err != nil {
		t.Fatalf("get promoted: %v", err)
	}
	if val != "wh-prod" {
		t.Errorf("promoted value = %q, want %q", val, "wh-prod")
	}
}

func TestMCPEnvPromote_DryRun(t *testing.T) {
	v, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	data := callEnvTool(t, ctx, cs, "vault_env_promote", map[string]any{
		"group":    "liftclub",
		"keys":     []string{"STRIPE_WEBHOOK_SECRET"},
		"from_env": "production",
		"to_env":   "preview",
		"dry_run":  true,
	})

	var out envPromoteOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Promoted) != 1 {
		t.Fatalf("promoted = %d, want 1", len(out.Promoted))
	}

	// Value should NOT have been promoted.
	_, err := v.GetSecret("liftclub-preview", "STRIPE_WEBHOOK_SECRET")
	if err == nil {
		t.Error("STRIPE_WEBHOOK_SECRET should not exist in preview after dry-run")
	}
}

func TestMCPEnvPromote_NoValuesReturned(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	data := callEnvTool(t, ctx, cs, "vault_env_promote", map[string]any{
		"group":    "liftclub",
		"keys":     []string{"STRIPE_SECRET_KEY"},
		"from_env": "production",
		"to_env":   "preview",
	})

	// Ensure no secret values appear in the output.
	text := string(data)
	if contains(text, "sk-prod") || contains(text, "sk-preview") {
		t.Error("secret value found in promote output")
	}
}

func TestMCPEnvSeal(t *testing.T) {
	v, _, cs, identity := setupEnvGroupTestVault(t)
	ctx := context.Background()

	// Get the identity's public recipient string.
	pubRecipient := crypto.EncodeRecipient(identity.Recipient())

	data := callEnvTool(t, ctx, cs, "vault_env_seal", map[string]any{
		"group":      "liftclub",
		"recipients": []string{pubRecipient},
	})

	var out envSealOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Bytes == 0 {
		t.Error("sealed blob should not be empty")
	}
	if out.SealedBase64 == "" {
		t.Error("sealed base64 should not be empty")
	}
	if len(out.Environments) != 2 {
		t.Errorf("env count = %d, want 2", len(out.Environments))
	}
	if out.RecipientCount != 1 {
		t.Errorf("recipient count = %d, want 1", out.RecipientCount)
	}

	// Ensure no secret values appear in the output.
	text := string(data)
	if strings.Contains(text, "prod-db") || strings.Contains(text, "sk-prod") || strings.Contains(text, "wh-prod") {
		t.Error("secret value found in seal output")
	}

	// Decrypt the sealed blob and verify sections.
	sealedBytes, err := base64.StdEncoding.DecodeString(out.SealedBase64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	plaintext, err := encryptedenv.DecryptV2(identity, sealedBytes)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	ptext := string(plaintext)
	if !strings.Contains(ptext, "--- tvault-env:production ---") {
		t.Error("missing production section header")
	}
	if !strings.Contains(ptext, "--- tvault-env:preview ---") {
		t.Error("missing preview section header")
	}
	if !strings.Contains(ptext, "--- end ---") {
		t.Error("missing end marker")
	}
	if !strings.Contains(ptext, "prod-db") {
		t.Error("production DATABASE_URL not found in decrypted blob")
	}

	_ = v // keep reference
}

func TestMCPEnvInherit(t *testing.T) {
	v, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	data := callEnvTool(t, ctx, cs, "vault_env_inherit", map[string]any{
		"group": "liftclub",
		"env":   "preview",
		"from":  "production",
	})

	var out envInheritOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.InheritsFrom != "production" {
		t.Errorf("inherits_from = %q, want %q", out.InheritsFrom, "production")
	}

	// Verify inheritance works — STRIPE_WEBHOOK_SECRET should now resolve from production.
	val, source, err := v.ResolveKey("liftclub", "preview", "STRIPE_WEBHOOK_SECRET")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if val != "wh-prod" {
		t.Errorf("resolved value = %q, want %q", val, "wh-prod")
	}
	if source != "production" {
		t.Errorf("source = %q, want %q", source, "production")
	}
}

func TestMCPEnvInherited(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	// Set up inheritance first.
	_ = callEnvTool(t, ctx, cs, "vault_env_inherit", map[string]any{
		"group": "liftclub",
		"env":   "preview",
		"from":  "production",
	})

	data := callEnvTool(t, ctx, cs, "vault_env_inherited", map[string]any{
		"group": "liftclub",
		"env":   "preview",
	})

	var out envInheritedOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// STRIPE_WEBHOOK_SECRET should be inherited from production.
	found := false
	for _, k := range out.Keys {
		if k.Key == "STRIPE_WEBHOOK_SECRET" {
			found = true
			if k.Pinned {
				t.Error("STRIPE_WEBHOOK_SECRET should not be pinned")
			}
			if k.Source != "inherited:production" {
				t.Errorf("source = %q, want %q", k.Source, "inherited:production")
			}
		}
	}
	if !found {
		t.Error("STRIPE_WEBHOOK_SECRET not found in inherited list")
	}

	// DATABASE_URL should be local/pinned (it exists in preview).
	for _, k := range out.Keys {
		if k.Key == "DATABASE_URL" {
			if k.Source != "local" {
				t.Errorf("DATABASE_URL source = %q, want %q", k.Source, "local")
			}
			if !k.Pinned {
				t.Error("DATABASE_URL should be pinned (local)")
			}
		}
	}
}

func TestMCPEnvSeal_SpecificEnvs(t *testing.T) {
	_, _, cs, identity := setupEnvGroupTestVault(t)
	ctx := context.Background()

	pubRecipient := crypto.EncodeRecipient(identity.Recipient())

	data := callEnvTool(t, ctx, cs, "vault_env_seal", map[string]any{
		"group":      "liftclub",
		"recipients": []string{pubRecipient},
		"envs":       []string{"preview"},
	})

	var out envSealOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Environments) != 1 {
		t.Fatalf("env count = %d, want 1", len(out.Environments))
	}
	if out.Environments[0] != "preview" {
		t.Errorf("env = %q, want %q", out.Environments[0], "preview")
	}

	// Decrypt and verify only preview section is present.
	sealedBytes, _ := base64.StdEncoding.DecodeString(out.SealedBase64)
	plaintext, err := encryptedenv.DecryptV2(identity, sealedBytes)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	ptext := string(plaintext)
	if strings.Contains(ptext, "production") {
		t.Error("production section should not be in preview-only seal")
	}
	if !strings.Contains(ptext, "preview") {
		t.Error("preview section missing")
	}
}

func TestMCPGetSecret_WithGroupEnv(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	// Set up inheritance: preview inherits from production.
	_ = callEnvTool(t, ctx, cs, "vault_env_inherit", map[string]any{
		"group": "liftclub",
		"env":   "preview",
		"from":  "production",
	})

	// STRIPE_WEBHOOK_SECRET exists only in production — should resolve from base.
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "vault_get_secret",
		Arguments: map[string]any{
			"key":   "STRIPE_WEBHOOK_SECRET",
			"group": "liftclub",
			"env":   "preview",
		},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.IsError {
		t.Fatalf("error: %s", res.Content[0].(*sdkmcp.TextContent).Text)
	}
	text := res.Content[0].(*sdkmcp.TextContent).Text
	var out getSecretOutput
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Value != "wh-prod" {
		t.Errorf("value = %q, want %q", out.Value, "wh-prod")
	}
	if out.Source != "production" {
		t.Errorf("source = %q, want %q", out.Source, "production")
	}
}

func TestMCPGetSecret_GroupEnv_LocalOverride(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	// Set up inheritance.
	_ = callEnvTool(t, ctx, cs, "vault_env_inherit", map[string]any{
		"group": "liftclub",
		"env":   "preview",
		"from":  "production",
	})

	// DATABASE_URL exists in both — preview should win.
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "vault_get_secret",
		Arguments: map[string]any{
			"key":   "DATABASE_URL",
			"group": "liftclub",
			"env":   "preview",
		},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	text := res.Content[0].(*sdkmcp.TextContent).Text
	var out getSecretOutput
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Value != "preview-db" {
		t.Errorf("value = %q, want %q (local should override)", out.Value, "preview-db")
	}
	if out.Source != "preview" {
		t.Errorf("source = %q, want %q", out.Source, "preview")
	}
}

func TestMCPGetSecret_NoGroupEnv_Unchanged(t *testing.T) {
	_, _, cs, _ := setupEnvGroupTestVault(t)
	ctx := context.Background()

	// Without group/env, should work as before (backward compat).
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "vault_get_secret",
		Arguments: map[string]any{
			"key":     "DATABASE_URL",
			"project": "liftclub",
		},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	text := res.Content[0].(*sdkmcp.TextContent).Text
	var out getSecretOutput
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Value != "prod-db" {
		t.Errorf("value = %q, want %q", out.Value, "prod-db")
	}
	if out.Source != "" {
		t.Errorf("source = %q, want empty (no group)", out.Source)
	}
}

// --- helpers ---

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
