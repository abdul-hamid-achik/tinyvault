package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestRunWithEnvFileAndInterpolation is the end-to-end happy path:
// commit a .env with a tvault:// placeholder, run a command, the
// placeholder is resolved against the vault.
func TestRunWithEnvFileAndInterpolation(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "DATABASE_URL", "postgres://resolved"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// Write a .env that references the vault.
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("DATABASE_URL=${tvault://DATABASE_URL}\nPLAIN=hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Configure 'tvault run' to use the env file.
	oldEnvFile := runEnvFile
	runEnvFile = envFile
	defer func() { runEnvFile = oldEnvFile }()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	out := captureStdout(t, func() {
		// Run a shell command that prints the env vars.
		if err := runRun(cmd, []string{"sh", "-c", "echo DB=$DATABASE_URL PLAIN=$PLAIN"}); err != nil {
			t.Fatalf("runRun: %v", err)
		}
	})

	got := strings.TrimSpace(string(out))
	want := "DB=postgres://resolved PLAIN=hello"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestRunWithEnvFileVaultOverride ensures that when a .env defines
// a key that the vault also has, the vault wins (vault is the
// source of truth at run time).
func TestRunWithEnvFileVaultOverride(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "API_KEY", "from-vault"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("API_KEY=from-env\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldEnvFile := runEnvFile
	runEnvFile = envFile
	defer func() { runEnvFile = oldEnvFile }()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	out := captureStdout(t, func() {
		if err := runRun(cmd, []string{"sh", "-c", "echo $API_KEY"}); err != nil {
			t.Fatalf("runRun: %v", err)
		}
	})

	got := strings.TrimSpace(string(out))
	if got != "from-vault" {
		t.Errorf("expected vault to win, got %q", got)
	}
}
