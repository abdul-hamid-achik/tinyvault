package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func setVersionsForCLI(t *testing.T, vaultPath string, key string, vals ...string) {
	t.Helper()
	v := openTestVault(t, vaultPath)
	for _, val := range vals {
		if err := v.SetSecret("default", key, val); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
	v.Close()
}

func TestHistoryCommand(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "K", "a", "b", "c")

	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	out := captureStdout(t, func() {
		if err := runHistory(nil, []string{"K"}); err != nil {
			t.Fatalf("history: %v", err)
		}
	})
	var doc struct {
		Key      string `json:"key"`
		Versions []struct {
			Version int `json:"version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("history json: %v\n%s", err, out)
	}
	if doc.Key != "K" || len(doc.Versions) != 3 {
		t.Errorf("unexpected history: %+v", doc)
	}
}

func TestHistoryCommandMissingKey(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	if err := runHistory(nil, []string{"NOPE"}); err == nil {
		t.Fatal("history of a missing key should error")
	}
}

func TestRollbackCommand(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "K", "a", "b")

	oldTo := rollbackToVersion
	rollbackToVersion = 1
	defer func() { rollbackToVersion = oldTo }()

	if err := runRollback(nil, []string{"K"}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	// Verify the current value is now v1's value.
	v := openTestVault(t, vaultPath)
	defer v.Close()
	got, err := v.GetSecret("default", "K")
	if err != nil || got != "a" {
		t.Errorf("after rollback current = %q (err %v), want \"a\"", got, err)
	}
}

func TestRollbackCommandMissingTo(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	oldTo := rollbackToVersion
	rollbackToVersion = 0
	defer func() { rollbackToVersion = oldTo }()
	if err := runRollback(nil, []string{"K"}); err == nil {
		t.Fatal("rollback without --to should error")
	}
}

func TestRollbackCommandBadVersion(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "K", "a")
	oldTo := rollbackToVersion
	rollbackToVersion = 99
	defer func() { rollbackToVersion = oldTo }()
	if err := runRollback(nil, []string{"K"}); err == nil {
		t.Fatal("rollback to a nonexistent version should error")
	}
}

func TestGetVersionFlag(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "K", "first", "second")

	oldV, oldFrom := getVersion, getFromFile
	getVersion, getFromFile = 1, ""
	defer func() { getVersion, getFromFile = oldV, oldFrom }()

	out := captureStdout(t, func() {
		if err := runGet(nil, []string{"K"}); err != nil {
			t.Fatalf("get --version 1: %v", err)
		}
	})
	if strings.TrimSpace(string(out)) != "first" {
		t.Errorf("get --version 1 = %q, want \"first\"", out)
	}
}

func TestGetVersionAndFromMutuallyExclusive(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	oldV, oldFrom := getVersion, getFromFile
	getVersion, getFromFile = 2, ".env"
	defer func() { getVersion, getFromFile = oldV, oldFrom }()
	if err := runGet(nil, []string{"K"}); err == nil {
		t.Fatal("--from with --version should error")
	}
}
