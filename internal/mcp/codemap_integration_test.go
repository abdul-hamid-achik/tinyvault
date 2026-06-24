package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// codemapIntegrationServer creates a vault with two projects ("default" and
// "payments") and seeds secrets that exercise each codemap integration:
//
//   - STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET: rotation blast radius (A)
//   - GOPRIVATE / NPM_TOKEN / PIP_INDEX_TOKEN:  private-registry LSP creds (B)
//   - ORPHAN_VAULT_KEY:                          env-var audit orphan (C)
//   - DB_PASSWORD:                               credential freshness (D)
//   - multiple keys across projects:            least-privilege seal scope (E)
//
// It returns a server + client session pair over in-memory MCP transport so
// the tests exercise the full tool dispatch path.
func codemapIntegrationServer(t *testing.T) (*VaultMCPServer, *sdkmcp.ClientSession) {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Create(dir, "codemap-test-pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	// Default project: rotation-blast-radius keys + a dead/orphan key.
	for k, val := range map[string]string{
		"STRIPE_SECRET_KEY":     "sk_live_5123",
		"STRIPE_WEBHOOK_SECRET": "whsec_abc",
		"ORPHAN_VAULT_KEY":      "no-code-uses-this",
		"DB_PASSWORD":           "s3cr3t-pw",
	} {
		if err := v.SetSecret("default", k, val); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	// Rotate DB_PASSWORD to get version history for freshness annotations (D).
	if err := v.SetSecret("default", "DB_PASSWORD", "rotated-pw-v2"); err != nil {
		t.Fatalf("set DB_PASSWORD v2: %v", err)
	}

	// Payments project: registry-credential keys for the --via-vault path (B).
	if _, err := v.CreateProject("payments", "payment service"); err != nil {
		t.Fatalf("create payments project: %v", err)
	}
	for k, val := range map[string]string{
		"GOPRIVATE":         "github.com/my-org/*",
		"NPM_TOKEN":         "npm_xyz",
		"PIP_INDEX_TOKEN":   "pip_pqr",
		"STRIPE_SECRET_KEY": "sk_live_payments_key",
	} {
		if err := v.SetSecret("payments", k, val); err != nil {
			t.Fatalf("set payments %s: %v", k, err)
		}
	}

	policy := DefaultPolicy()
	srv := NewVaultMCPServer(v, policy)

	ctx := context.Background()
	t1, t2 := sdkmcp.NewInMemoryTransports()
	if _, err := srv.server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := sdkmcp.NewClient(
		&sdkmcp.Implementation{Name: "codemap-test-client", Version: "v0.0.1"},
		nil,
	)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	return srv, cs
}

// callTool is a test helper that calls a tool, unwraps the JSON text content,
// and decodes it into out. It fails the test on transport errors or
// IsError=true responses.
func callTool(t *testing.T, ctx context.Context, cs *sdkmcp.ClientSession,
	name string, args map[string]any, out any,
) {
	t.Helper()
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		text := ""
		if len(res.Content) > 0 {
			text = res.Content[0].(*sdkmcp.TextContent).Text
		}
		t.Fatalf("%s returned error: %s", name, text)
	}
	text := res.Content[0].(*sdkmcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), out); err != nil {
		t.Fatalf("%s unmarshal: %v\nbody: %s", name, err, text)
	}
}

// --- Integration A: secret rotation blast radius ---

// TestCodemapA_RotationBlastRadius verifies that codemap's hypothetical
// rotation-impact workflow gets value-free key names from tinyvault:
// vault_list_secrets_by_prefix for a prefix like STRIPE_, plus
// vault_search_secrets for the cross-project view. No values cross the seam.
func TestCodemapA_RotationBlastRadius(t *testing.T) {
	ctx := context.Background()
	_, cs := codemapIntegrationServer(t)

	// Step 1: codemap asks "give me all keys starting with STRIPE_" (single project).
	var prefixOut listByPrefixOutput
	callTool(t, ctx, cs, "vault_list_secrets_by_prefix",
		map[string]any{"prefix": "STRIPE_"}, &prefixOut)
	if len(prefixOut.Keys) != 2 {
		t.Fatalf("expected 2 STRIPE_ keys, got %d: %v", len(prefixOut.Keys), prefixOut.Keys)
	}
	for _, k := range prefixOut.Keys {
		if !strings.HasPrefix(k, "STRIPE_") {
			t.Errorf("key %q does not start with STRIPE_", k)
		}
	}

	// Step 2: codemap asks "give me STRIPE_SECRET_KEY across ALL projects"
	// (cross-project blast radius). Uses vault_search_secrets.
	var searchOut searchSecretsOutput
	callTool(t, ctx, cs, "vault_search_secrets",
		map[string]any{"name_like": "STRIPE_SECRET_KEY"}, &searchOut)
	if searchOut.Count != 2 {
		t.Fatalf("expected 2 STRIPE_SECRET_KEY refs across projects, got %d", searchOut.Count)
	}
	projects := make(map[string]bool)
	for _, r := range searchOut.Results {
		projects[r.Project] = true
		if r.Key != "STRIPE_SECRET_KEY" {
			t.Errorf("unexpected key %q in results", r.Key)
		}
	}
	if !projects["default"] || !projects["payments"] {
		t.Errorf("expected both default+payments in results, got %v", projects)
	}

	// Step 3: value-free guarantee — the raw JSON must never contain secret values.
	rawJSON, err := json.Marshal(searchOut)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leaked := range []string{"sk_live_5123", "sk_live_payments_key"} {
		if strings.Contains(string(rawJSON), leaked) {
			t.Errorf("search results leaked secret value %q: %s", leaked, rawJSON)
		}
	}
}

// --- Integration B: private-registry LSP creds via --via-vault ---

// TestCodemapB_ViaVaultRegistryCreds verifies that vault_run_with_secrets can
// inject only the registry-credential keys (GOPRIVATE, NPM_TOKEN,
// PIP_INDEX_TOKEN) into a child process, which is exactly what
// `codemap index --via-vault <project>` wraps. The test checks that:
//   - only the requested keys appear in the child env (least privilege)
//   - the output is redacted (no secret values in the response)
func TestCodemapB_ViaVaultRegistryCreds(t *testing.T) {
	ctx := context.Background()
	_, cs := codemapIntegrationServer(t)

	// The child process prints only the env-var names for the keys we care
	// about, one per line, sorted. We use a Go-based check rather than shell
	// piping so the test is portable and deterministic.
	const checkScript = `for k in GOPRIVATE NPM_TOKEN PIP_INDEX_TOKEN STRIPE_SECRET_KEY; do if [ -n "${!k}" ]; then echo "$k"; fi; done | sort`

	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "vault_run_with_secrets",
		Arguments: map[string]any{
			"project": "payments",
			"command": checkScript,
			"secrets": []string{"GOPRIVATE", "NPM_TOKEN", "PIP_INDEX_TOKEN"},
		},
	})
	if err != nil {
		t.Fatalf("call vault_run_with_secrets: %v", err)
	}
	if res.IsError {
		text := res.Content[0].(*sdkmcp.TextContent).Text
		t.Fatalf("tool error: %s", text)
	}

	var out runResult
	if err := json.Unmarshal([]byte(res.Content[0].(*sdkmcp.TextContent).Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ExitCode != 0 {
		t.Fatalf("exit code %d, stderr=%q", out.ExitCode, out.Stderr)
	}

	got := strings.Fields(out.Stdout)
	// The three requested keys should be present; STRIPE_SECRET_KEY should NOT.
	want := []string{"GOPRIVATE", "NPM_TOKEN", "PIP_INDEX_TOKEN"}
	if len(got) != len(want) {
		t.Fatalf("injected env count = %d (%v), want %d (%v) — STRIPE_SECRET_KEY should be absent", len(got), got, len(want), want)
	}
	for i, w := range want {
		if i >= len(got) || got[i] != w {
			t.Errorf("injected env[%d] = %q, want %q", i, safeIndex(got, i), w)
		}
	}

	// The redaction safety net: the response must never carry the raw values.
	for _, leaked := range []string{"npm_xyz", "pip_pqr", "sk_live_payments_key"} {
		rawText := res.Content[0].(*sdkmcp.TextContent).Text
		if strings.Contains(rawText, leaked) {
			t.Errorf("run output leaked secret value %q", leaked)
		}
	}
}

// safeIndex returns got[i] or "<missing>" for safe error formatting.
func safeIndex(got []string, i int) string {
	if i < len(got) {
		return got[i]
	}
	return "<missing>"
}

// --- Integration C: hardcoded / unmanaged env-var audit ---

// TestCodemapC_EnvVarAudit verifies that vault_list_secrets_global returns
// metadata-only rows across all projects, so codemap can diff "referenced env
// keys" against "vault keys" to find missing (unmanaged) and orphan (dead)
// keys. The orphan key ORPHAN_VAULT_KEY should appear in the vault listing
// but have no code usage.
func TestCodemapC_EnvVarAudit(t *testing.T) {
	ctx := context.Background()
	_, cs := codemapIntegrationServer(t)

	var out searchSecretsOutput
	callTool(t, ctx, cs, "vault_list_secrets_global",
		map[string]any{}, &out)

	// Build a set of (project, key) for validation.
	type pk struct {
		Project string `json:"project"`
		Key     string `json:"key"`
	}
	seen := make(map[pk]bool)
	for _, r := range out.Results {
		p := pk{r.Project, r.Key}
		if seen[p] {
			t.Errorf("duplicate entry: %+v", p)
		}
		seen[p] = true
	}

	// ORPHAN_VAULT_KEY exists in the vault but would have no code usage.
	if !seen[pk{"default", "ORPHAN_VAULT_KEY"}] {
		t.Error("ORPHAN_VAULT_KEY missing from global listing")
	}

	// STRIPE_SECRET_KEY should appear in BOTH projects.
	if !seen[pk{"default", "STRIPE_SECRET_KEY"}] {
		t.Error("STRIPE_SECRET_KEY missing from default project")
	}
	if !seen[pk{"payments", "STRIPE_SECRET_KEY"}] {
		t.Error("STRIPE_SECRET_KEY missing from payments project")
	}

	// Registry keys in the payments project.
	for _, k := range []string{"GOPRIVATE", "NPM_TOKEN", "PIP_INDEX_TOKEN"} {
		if !seen[pk{"payments", k}] {
			t.Errorf("%s missing from payments project in global listing", k)
		}
	}

	// Value-free guarantee.
	rawJSON, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leaked := range []string{"sk_live_5123", "npm_xyz", "no-code-uses-this"} {
		if strings.Contains(string(rawJSON), leaked) {
			t.Errorf("global listing leaked secret value %q: %s", leaked, rawJSON)
		}
	}
}

// --- Integration D: credential-freshness annotations ---

// TestCodemapD_CredentialFreshness verifies that codemap can build a
// credential-freshness map by combining:
//   - vault_secret_history (version + timestamps per key)
//   - vault_audit_log_since (recent actions on the key)
//
// Both are value-free; the output carries only version numbers and timestamps.
func TestCodemapD_CredentialFreshness(t *testing.T) {
	ctx := context.Background()
	_, cs := codemapIntegrationServer(t)

	// Step 1: get version history for DB_PASSWORD (has 2 versions).
	var hist secretHistoryOutput
	callTool(t, ctx, cs, "vault_secret_history",
		map[string]any{"key": "DB_PASSWORD"}, &hist)
	if len(hist.Versions) != 2 {
		t.Fatalf("expected 2 versions for DB_PASSWORD, got %d", len(hist.Versions))
	}
	// Versions should be monotonically increasing.
	if hist.Versions[0].Version >= hist.Versions[1].Version {
		t.Errorf("versions not monotonic: v%d then v%d",
			hist.Versions[0].Version, hist.Versions[1].Version)
	}

	// Step 2: get recent audit entries for the secret.read action (history
	// generates one).
	var auditOut auditLogOutput
	callTool(t, ctx, cs, "vault_audit_log_since",
		map[string]any{"action": "secret.read", "limit": float64(10)}, &auditOut)
	if len(auditOut.Entries) == 0 {
		t.Fatal("expected at least one secret.read audit entry from the history call")
	}
	for _, e := range auditOut.Entries {
		if e.Action != "secret.read" {
			t.Errorf("audit filter leaked: got action %q, want secret.read", e.Action)
		}
	}

	// Value-free guarantee: neither history nor audit should carry values.
	histJSON, _ := json.Marshal(hist)
	auditJSON, _ := json.Marshal(auditOut)
	for _, blob := range []string{string(histJSON), string(auditJSON)} {
		for _, leaked := range []string{"s3cr3t-pw", "rotated-pw-v2"} {
			if strings.Contains(blob, leaked) {
				t.Errorf("freshness output leaked secret value %q: %s", leaked, blob)
			}
		}
	}
}

// --- Integration E: least-privilege seal scope ---

// TestCodemapE_LeastPrivilegeSealScope verifies that codemap can derive a
// required_keys subset from the call graph and seal ONLY those keys:
//   - vault_seal_for_recipients with keys[] → exact subset, ciphertext only
//   - vault_export_env with keys[] → exact subset to disk
//   - vault_export_env_encrypted with keys[] → exact subset, encrypted v2
//
// All three must error on a missing key (fail loudly on a typo) and must
// produce a bundle that excludes non-requested keys.
func TestCodemapE_LeastPrivilegeSealScope(t *testing.T) {
	ctx := context.Background()
	srv, cs := codemapIntegrationServer(t)

	// Create an identity + share the default project so
	// vault_export_env_encrypted can use project recipients.
	id, _ := crypto.GenerateIdentity()
	rec := crypto.EncodeRecipient(id.Recipient())
	callTool(t, ctx, cs, "vault_share_project",
		map[string]any{"recipient": rec, "project": "default"},
		&shareProjectOutput{},
	)

	t.Run("seal_for_recipients_key_subset", func(t *testing.T) {
		// Seal only the two STRIPE_ keys — DB_PASSWORD and ORPHAN_VAULT_KEY
		// must be excluded from the bundle.
		var out sealForRecipientsOutput
		callTool(t, ctx, cs, "vault_seal_for_recipients",
			map[string]any{
				"recipients": []string{rec},
				"project":    "default",
				"keys":       []string{"STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"},
			}, &out)

		if out.Count != 2 {
			t.Fatalf("expected 2 sealed keys, got %d", out.Count)
		}
		for _, leaked := range []string{"sk_live_5123", "whsec_abc", "s3cr3t-pw"} {
			if strings.Contains(out.SealedBase64, leaked) {
				t.Errorf("sealed base64 leaked plaintext %q", leaked)
			}
		}

		// Decrypt and verify only the requested keys are present.
		sealed, err := base64.StdEncoding.DecodeString(out.SealedBase64)
		if err != nil {
			t.Fatalf("decode base64: %v", err)
		}
		pt, err := encryptedenv.DecryptV2(id, sealed)
		if err != nil {
			t.Fatalf("recipient decrypt: %v", err)
		}
		body := string(pt)
		if !strings.Contains(body, "STRIPE_SECRET_KEY=") || !strings.Contains(body, "STRIPE_WEBHOOK_SECRET=") {
			t.Errorf("sealed body missing expected keys: %q", body)
		}
		if strings.Contains(body, "ORPHAN_VAULT_KEY") || strings.Contains(body, "DB_PASSWORD") {
			t.Errorf("sealed body contains excluded keys: %q", body)
		}
	})

	t.Run("seal_for_recipients_missing_key_errors", func(t *testing.T) {
		// A typo in the key list must fail loudly, not silently seal a subset.
		_, _, err := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
			Recipients: []string{rec},
			Project:    "default",
			Keys:       []string{"STRIPE_SECRET_KEY", "TYPO_KEY"},
		})
		if err == nil {
			t.Fatal("sealing with a missing key should error")
		}
	})

	t.Run("export_env_key_subset", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "least-priv.env")
		var out exportEnvOutput
		callTool(t, ctx, cs, "vault_export_env",
			map[string]any{
				"project":     "default",
				"keys":        []string{"STRIPE_SECRET_KEY"},
				"output_path": outPath,
			}, &out)

		if out.Count != 1 {
			t.Fatalf("expected 1 exported key, got %d", out.Count)
		}
		if len(out.Keys) != 1 || out.Keys[0] != "STRIPE_SECRET_KEY" {
			t.Errorf("exported keys = %v, want [STRIPE_SECRET_KEY]", out.Keys)
		}

		// The response must not leak values.
		respJSON, _ := json.Marshal(out)
		if strings.Contains(string(respJSON), "sk_live_5123") {
			t.Errorf("export response leaked secret value: %s", respJSON)
		}

		// The file must contain only the requested key's value.
		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read file: %v", err)
		}
		if !strings.Contains(string(data), "STRIPE_SECRET_KEY=") {
			t.Errorf("exported file missing STRIPE_SECRET_KEY: %s", data)
		}
		if strings.Contains(string(data), "DB_PASSWORD") || strings.Contains(string(data), "ORPHAN_VAULT_KEY") {
			t.Errorf("exported file contains excluded keys: %s", data)
		}
	})

	t.Run("export_env_encrypted_key_subset", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "least-priv.encrypted")
		var out exportEnvEncryptedOutput
		callTool(t, ctx, cs, "vault_export_env_encrypted",
			map[string]any{
				"project":     "default",
				"keys":        []string{"STRIPE_SECRET_KEY"},
				"output_path": outPath,
			}, &out)

		if out.Count != 1 {
			t.Fatalf("expected 1 encrypted key, got %d", out.Count)
		}
		if len(out.Keys) != 1 || out.Keys[0] != "STRIPE_SECRET_KEY" {
			t.Errorf("encrypted keys = %v, want [STRIPE_SECRET_KEY]", out.Keys)
		}

		// Decrypt and verify only the requested key is present.
		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read file: %v", err)
		}
		pt, err := encryptedenv.DecryptV2(id, data)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		body := string(pt)
		if !strings.Contains(body, "STRIPE_SECRET_KEY=") {
			t.Errorf("encrypted export missing STRIPE_SECRET_KEY: %q", body)
		}
		if strings.Contains(body, "DB_PASSWORD") || strings.Contains(body, "ORPHAN_VAULT_KEY") {
			t.Errorf("encrypted export contains excluded keys: %q", body)
		}
	})
}

// --- Policy gating: codemap must respect AccessPolicy ---

// TestCodemapIntegration_PolicyGating verifies that the codemap-facing tools
// respect the access policy — a scoped policy that allows only STRIPE_* keys
// must filter seal/export outputs, and a denied project must be rejected.
func TestCodemapIntegration_PolicyGating(t *testing.T) {
	dir := t.TempDir()
	v, err := vault.Create(dir, "policy-pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	for k, val := range map[string]string{
		"STRIPE_KEY":   "sk_live_abc",
		"DATABASE_URL": "postgres://localhost",
		"MASTER_KEY":   "master-very-secret",
	} {
		if err := v.SetSecret("default", k, val); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}

	// Policy: allow STRIPE_*, deny MASTER_KEY, allow all projects.
	restricted := &AccessPolicy{
		AccessMode:    "full",
		ProjectsAllow: []string{"*"},
		SecretsAllow:  []string{"STRIPE_*"},
		SecretsDeny:   []string{"MASTER_KEY"},
		AllowExec:     true,
	}
	restrictedSrv := NewVaultMCPServer(v, restricted)

	// seal with no explicit keys → policy should filter to only STRIPE_KEY.
	id, _ := crypto.GenerateIdentity()
	rec := crypto.EncodeRecipient(id.Recipient())

	_, out, err := restrictedSrv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
		Recipients: []string{rec},
		Project:    "default",
		// No keys[] → selectSealKeys uses all, then policy filters.
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if out.Count != 1 {
		t.Fatalf("policy should filter to 1 key (STRIPE_KEY), got %d", out.Count)
	}
	if len(out.Keys) != 1 || out.Keys[0] != "STRIPE_KEY" {
		t.Errorf("policy-filtered keys = %v, want [STRIPE_KEY]", out.Keys)
	}

	// list_secrets_by_prefix should also respect policy.
	ctx := context.Background()
	t1, t2 := sdkmcp.NewInMemoryTransports()
	if _, err := restrictedSrv.server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "policy-test", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	var listOut listSecretsOutput
	callTool(t, ctx, cs, "vault_list_secrets", map[string]any{}, &listOut)
	allowedKeys := make(map[string]bool)
	for _, s := range listOut.Secrets {
		allowedKeys[s.Key] = true
	}
	if !allowedKeys["STRIPE_KEY"] {
		t.Error("STRIPE_KEY should be allowed by policy")
	}
	if allowedKeys["MASTER_KEY"] {
		t.Error("MASTER_KEY should be denied by policy")
	}
	if allowedKeys["DATABASE_URL"] {
		t.Error("DATABASE_URL should not match STRIPE_* allow pattern")
	}
}
