package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func TestDiff(t *testing.T) {
	dir := t.TempDir()
	v, err := ivault.Create(dir, "p")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for k, val := range map[string]string{"DB_URL": "vaultdb", "API_KEY": "samekey", "PORT": "8080"} {
		if err := v.SetSecret("default", k, val); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	v.Close()

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("API_KEY=samekey\nPORT=9090\nEXTRA=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldProject, oldVals, oldJSON, oldVaultDir := projectName, diffValues, jsonOutput, vaultDir
	t.Cleanup(func() {
		projectName, diffValues, jsonOutput, vaultDir = oldProject, oldVals, oldJSON, oldVaultDir
	})
	vaultDir, projectName, jsonOutput = dir, "default", true
	t.Setenv("TVAULT_PASSPHRASE", "p")

	// Metadata-only (no --values, no unlock needed).
	diffValues = false
	out := captureStdout(t, func() {
		if err := runDiff(nil, []string{envPath}); err != nil {
			t.Fatalf("diff: %v", err)
		}
	})
	var r diffResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if len(r.OnlyInVault) != 1 || r.OnlyInVault[0] != "DB_URL" {
		t.Errorf("only_in_vault = %v, want [DB_URL]", r.OnlyInVault)
	}
	if len(r.OnlyInFile) != 1 || r.OnlyInFile[0] != "EXTRA" {
		t.Errorf("only_in_file = %v, want [EXTRA]", r.OnlyInFile)
	}
	if len(r.InBoth) != 2 {
		t.Errorf("in_both = %v, want [API_KEY PORT]", r.InBoth)
	}
	if r.InSync {
		t.Error("should not be in sync (keys differ)")
	}
	if r.ValueDiffs != nil {
		t.Error("metadata-only diff must not include value comparisons")
	}

	// With --values: API_KEY same, PORT differs.
	diffValues = true
	out2 := captureStdout(t, func() {
		if err := runDiff(nil, []string{envPath}); err != nil {
			t.Fatalf("diff --values: %v", err)
		}
	})
	var r2 diffResult
	if err := json.Unmarshal(out2, &r2); err != nil {
		t.Fatalf("unmarshal2: %v", err)
	}
	if r2.ValueDiffs["API_KEY"] != "same" {
		t.Errorf("API_KEY value = %q, want same", r2.ValueDiffs["API_KEY"])
	}
	if r2.ValueDiffs["PORT"] != "differs" {
		t.Errorf("PORT value = %q, want differs", r2.ValueDiffs["PORT"])
	}
}
