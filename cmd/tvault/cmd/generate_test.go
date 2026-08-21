package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func setupGenerateVault(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	v, err := ivault.Create(dir, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v.Close()

	oldDir, oldProject := vaultDir, projectName
	oldLen, oldCharset := generateLength, generateCharset
	t.Cleanup(func() {
		vaultDir, projectName = oldDir, oldProject
		generateLength, generateCharset = oldLen, oldCharset
		jsonOutput = false
	})
	vaultDir, projectName = dir, ""
	generateLength, generateCharset = 32, "alphanumeric"
	jsonOutput = false
	t.Setenv("TVAULT_PASSPHRASE", "test-passphrase")
	return dir
}

func TestGenerateStoresWithoutPrintingValue(t *testing.T) {
	dir := setupGenerateVault(t)
	generateLength = 24
	generateCharset = "hex"

	stdout := string(captureStdout(t, func() {
		if err := runGenerate(nil, []string{"SESSION_SECRET"}); err != nil {
			t.Fatalf("runGenerate: %v", err)
		}
	}))
	if strings.Contains(stdout, "SESSION_SECRET") {
		t.Errorf("stdout should be empty in text mode, got %q", stdout)
	}

	v, err := ivault.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer v.Close()
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	val, err := v.GetSecret("default", "SESSION_SECRET")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if len(val) != 24 {
		t.Fatalf("stored length = %d, want 24", len(val))
	}
	if strings.Contains(stdout, val) {
		t.Fatal("generated value leaked to stdout")
	}

	entries, err := v.ListAudit(store.AuditFilter{Action: "secret.generate"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected secret.generate audit entry")
	}
}

func TestGenerateJSONOmitsValue(t *testing.T) {
	dir := setupGenerateVault(t)
	jsonOutput = true
	generateLength = 16
	generateCharset = "alphanumeric"

	raw := captureStdout(t, func() {
		if err := runGenerate(nil, []string{"API_KEY"}); err != nil {
			t.Fatalf("runGenerate: %v", err)
		}
	})
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	if _, ok := doc["value"]; ok {
		t.Fatal("JSON must not include value")
	}
	if doc["key"] != "API_KEY" || doc["stored"] != true {
		t.Fatalf("JSON metadata: %+v", doc)
	}

	v, err := ivault.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer v.Close()
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	val, err := v.GetSecret("default", "API_KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if strings.Contains(string(raw), val) {
		t.Fatal("generated value leaked in JSON")
	}
}

func TestGenerateRejectsBadCharset(t *testing.T) {
	setupGenerateVault(t)
	generateCharset = "emoji"
	if err := runGenerate(nil, []string{"X"}); err == nil {
		t.Fatal("expected error for bad charset")
	}
}

func TestGenerateCommandRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, c := range rootCmd.Commands() {
		names[c.Name()] = true
	}
	if !names["generate"] {
		t.Fatal("generate command missing")
	}
}
