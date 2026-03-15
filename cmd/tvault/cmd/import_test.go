package cmd

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func TestRunImportExplicitFile(t *testing.T) {
	vaultPath, restore := setupImportCommandTest(t)
	defer restore()

	filePath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(filePath, []byte("API_KEY=abc123\nEMPTY=\n"), 0o600); err != nil {
		t.Fatalf("write dotenv file: %v", err)
	}

	if err := runImport(nil, []string{filePath}); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	v := openTestVault(t, vaultPath)
	if got, err := v.GetSecret("default", "API_KEY"); err != nil || got != "abc123" {
		t.Fatalf("API_KEY = %q, err = %v", got, err)
	}
	if got, err := v.GetSecret("default", "EMPTY"); err != nil || got != "" {
		t.Fatalf("EMPTY = %q, err = %v", got, err)
	}
}

func TestRunImportDryRunDoesNotWrite(t *testing.T) {
	vaultPath, restore := setupImportCommandTest(t)
	defer restore()

	importDryRun = true

	filePath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(filePath, []byte("API_KEY=abc123\n"), 0o600); err != nil {
		t.Fatalf("write dotenv file: %v", err)
	}

	if err := runImport(nil, []string{filePath}); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	v := openTestVault(t, vaultPath)
	if _, err := v.GetSecret("default", "API_KEY"); err == nil {
		t.Fatal("expected API_KEY to remain absent after dry run")
	}
}

func TestRunImportInteractiveDefaultSelection(t *testing.T) {
	vaultPath, restore := setupImportCommandTest(t)
	defer restore()

	importInteractive = true
	importEnvironment = "production"
	importDirectory = t.TempDir()
	importPromptInput = bufio.NewReader(bytes.NewBufferString("\nyes\n"))
	importPromptOutput = &bytes.Buffer{}
	importPromptIsTTY = func() bool { return true }

	for name, content := range map[string]string{
		".env":                  "API_KEY=base\nDB_HOST=base-host\n",
		".env.production":       "DB_HOST=prod-host\n",
		".env.local":            "API_KEY=local\n",
		".env.production.local": "FINAL_ONLY=final\n",
	} {
		if err := os.WriteFile(filepath.Join(importDirectory, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := runImport(nil, nil); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	v := openTestVault(t, vaultPath)
	if got, err := v.GetSecret("default", "API_KEY"); err != nil || got != "local" {
		t.Fatalf("API_KEY = %q, err = %v", got, err)
	}
	if got, err := v.GetSecret("default", "DB_HOST"); err != nil || got != "prod-host" {
		t.Fatalf("DB_HOST = %q, err = %v", got, err)
	}
	if got, err := v.GetSecret("default", "FINAL_ONLY"); err != nil || got != "final" {
		t.Fatalf("FINAL_ONLY = %q, err = %v", got, err)
	}
}

func TestResolveImportPathsRejectsInteractiveWithoutTTY(t *testing.T) {
	_, restore := setupImportCommandTest(t)
	defer restore()

	importInteractive = true
	importPromptIsTTY = func() bool { return false }

	if _, err := resolveImportPaths(nil); err == nil {
		t.Fatal("expected non-TTY interactive mode to fail")
	}
}

func TestRunImportRejectsUnsupportedExplicitFilename(t *testing.T) {
	_, restore := setupImportCommandTest(t)
	defer restore()

	filePath := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(filePath, []byte("API_KEY=abc123\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := runImport(nil, []string{filePath}); err == nil {
		t.Fatal("expected unsupported explicit filename to be rejected")
	}
}

func setupImportCommandTest(t *testing.T) (string, func()) {
	t.Helper()

	oldVaultDir := vaultDir
	oldProjectName := projectName
	oldImportDirectory := importDirectory
	oldImportEnvironment := importEnvironment
	oldImportFiles := append([]string(nil), importFiles...)
	oldImportOverwrite := importOverwrite
	oldImportDryRun := importDryRun
	oldImportInteractive := importInteractive
	oldPromptInput := importPromptInput
	oldPromptOutput := importPromptOutput
	oldPromptIsTTY := importPromptIsTTY

	vaultPath := t.TempDir()
	v, err := ivault.Create(vaultPath, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v.Close()

	vaultDir = vaultPath
	projectName = ""
	importDirectory = "."
	importEnvironment = ""
	importFiles = nil
	importOverwrite = false
	importDryRun = false
	importInteractive = false
	importPromptInput = bufio.NewReader(bytes.NewBuffer(nil))
	importPromptOutput = &bytes.Buffer{}
	importPromptIsTTY = func() bool { return true }

	t.Setenv("TVAULT_PASSPHRASE", "test-passphrase")

	return vaultPath, func() {
		vaultDir = oldVaultDir
		projectName = oldProjectName
		importDirectory = oldImportDirectory
		importEnvironment = oldImportEnvironment
		importFiles = oldImportFiles
		importOverwrite = oldImportOverwrite
		importDryRun = oldImportDryRun
		importInteractive = oldImportInteractive
		importPromptInput = oldPromptInput
		importPromptOutput = oldPromptOutput
		importPromptIsTTY = oldPromptIsTTY
	}
}

func openTestVault(t *testing.T, dir string) *ivault.Vault {
	t.Helper()

	v, err := ivault.Open(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}
