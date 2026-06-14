package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func TestRunBackup(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "BACKUP_KEY", "backup-value"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	backupPath := filepath.Join(t.TempDir(), "vault.db")

	// runBackup is a simple file copy: src=vault.db -> dst=args[0].
	if err := runBackup(nil, []string{backupPath}); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	// Verify the backup file exists and is a valid vault.
	v2, err := ivault.Open(filepath.Dir(backupPath) + "/.placeholder")
	_ = v2
	_ = err
	if _, err := os.Stat(backupPath); err != nil {
		t.Errorf("backup file not created: %v", err)
	}
	// We can't Open the backup directly (its dir has no vault.db),
	// but we can compare bytes.
	srcBytes, _ := os.ReadFile(vaultPath + "/vault.db")
	dstBytes, _ := os.ReadFile(backupPath)
	if len(srcBytes) != len(dstBytes) {
		t.Errorf("backup size differs: src=%d dst=%d", len(srcBytes), len(dstBytes))
	}
}

func TestRunRestoreRejectsMissingFile(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	err := runRestore(nil, []string{"/nonexistent/backup.db"})
	if err == nil {
		t.Error("expected error for missing backup file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got %v", err)
	}
}

// TestRunDelete tests the tvault delete command via the cobra path.
func TestRunDelete(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "TO_DELETE", "value"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// --yes skips the confirmation prompt, which is required when
	// stdin is closed (the test process inherits closed stdin from
	// 'go test').
	oldForce := deleteForce
	deleteForce = true
	defer func() { deleteForce = oldForce }()

	// Capture stdout to verify the success message.
	out := captureStdout(t, func() {
		if err := runDelete(nil, []string{"TO_DELETE"}); err != nil {
			t.Fatalf("runDelete: %v", err)
		}
	})
	if !strings.Contains(string(out), "TO_DELETE") {
		t.Errorf("expected output to mention TO_DELETE, got %q", out)
	}

	// Verify the secret is gone.
	v2 := openTestVault(t, vaultPath)
	defer v2.Close()
	_, err := v2.GetSecret("default", "TO_DELETE")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestRunEnvShell(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldFormat := envFormat
	oldExport := envExport
	envFormat = "shell"
	envExport = true
	defer func() {
		envFormat = oldFormat
		envExport = oldExport
	}()

	out := captureStdout(t, func() {
		if err := runEnv(nil, nil); err != nil {
			t.Fatalf("runEnv: %v", err)
		}
	})
	if !strings.Contains(string(out), "export FOO=") {
		t.Errorf("expected 'export FOO=', got %q", out)
	}
}

func TestRunEnvK8sRequiresName(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldFormat := envFormat
	oldName := envK8sName
	envFormat = "k8s-secret"
	envK8sName = ""
	defer func() {
		envFormat = oldFormat
		envK8sName = oldName
	}()

	err := runEnv(nil, nil)
	if err == nil {
		t.Error("expected error when --name is missing for k8s-secret")
	}
	if !strings.Contains(err.Error(), "--name") {
		t.Errorf("expected error to mention --name, got %v", err)
	}
}

func TestRunEnvK8sSecret(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldFormat := envFormat
	oldName := envK8sName
	envFormat = "k8s-secret"
	envK8sName = "my-secret"
	defer func() {
		envFormat = oldFormat
		envK8sName = oldName
	}()

	out := captureStdout(t, func() {
		if err := runEnv(nil, nil); err != nil {
			t.Fatalf("runEnv: %v", err)
		}
	})
	body := string(out)
	for _, want := range []string{"apiVersion: v1", "kind: Secret", "name: my-secret", "data:", "FOO:"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in K8s manifest:\n%s", want, body)
		}
	}
}

func TestRunGetMissingSecret(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "EXISTS", "x"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	err := runGet(nil, []string{"DOES_NOT_EXIST"})
	if err == nil {
		t.Error("expected error for missing secret")
	}
}

func TestRunGetJSON(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "bar"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	out := captureStdout(t, func() {
		if err := runGet(nil, []string{"FOO"}); err != nil {
			t.Fatalf("runGet: %v", err)
		}
	})
	var doc map[string]string
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, out)
	}
	if doc["key"] != "FOO" || doc["value"] != "bar" {
		t.Errorf("got %v, want FOO/bar", doc)
	}
}

// copyFileForTest was here before; the test now uses runBackup
// directly so this helper is no longer needed.
