package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePassphraseFile(t *testing.T, body string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte(body), perm); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadPassphraseFileAcceptsExportSyntax(t *testing.T) {
	// Mirrors a real ~/.config/secrets/env that a shell sources at startup.
	path := writePassphraseFile(t, "# secrets\nexport OTHER=x\nexport TVAULT_PASSPHRASE=hunter2\n", 0o600)

	got, err := readPassphraseFile(path)
	if err != nil {
		t.Fatalf("readPassphraseFile: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("passphrase = %q, want %q", got, "hunter2")
	}
}

// TestReadPassphraseFileRejectsLoosePermissions is the security-relevant case:
// the file guards every secret in the vault, so a group- or world-readable mode
// must fail rather than warn.
func TestReadPassphraseFileRejectsLoosePermissions(t *testing.T) {
	for _, perm := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		path := writePassphraseFile(t, "TVAULT_PASSPHRASE=hunter2\n", perm)
		// os.WriteFile is umask-filtered; set the mode explicitly.
		if err := os.Chmod(path, perm); err != nil {
			t.Fatal(err)
		}
		_, err := readPassphraseFile(path)
		if err == nil {
			t.Errorf("mode %#o was accepted; a readable-by-others passphrase file must be refused", perm)
			continue
		}
		if !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %#o: error should tell the user how to fix it, got %v", perm, err)
		}
	}
}

// TestPassphraseFileErrorsNeverEchoTheValue guards the rule that a passphrase
// must never reach an error string, a log, or the terminal.
func TestPassphraseFileErrorsNeverEchoTheValue(t *testing.T) {
	const secret = "super-secret-passphrase"
	path := writePassphraseFile(t, "TVAULT_PASSPHRASE="+secret+"\n", 0o644)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := readPassphraseFile(path)
	if err == nil {
		t.Fatal("expected a permissions error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the passphrase: %v", err)
	}
}

func TestReadPassphraseFileMissingKey(t *testing.T) {
	path := writePassphraseFile(t, "SOMETHING_ELSE=1\n", 0o600)
	_, err := readPassphraseFile(path)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want a 'not found' error, got %v", err)
	}
}

func TestReadPassphraseFileEmptyValue(t *testing.T) {
	path := writePassphraseFile(t, "TVAULT_PASSPHRASE=\n", 0o600)
	if _, err := readPassphraseFile(path); err == nil {
		t.Fatal("an empty passphrase must be rejected, not returned as a valid unlock")
	}
}

func TestPassphraseFilePathPrecedence(t *testing.T) {
	cfg := Config{Agent: AgentConfig{PassphraseFile: "/from/config"}}

	t.Setenv(envPassphraseFile, "")
	if got := passphraseFilePath(cfg); got != "/from/config" {
		t.Errorf("with no env var, want the config path, got %q", got)
	}

	t.Setenv(envPassphraseFile, "/from/env")
	if got := passphraseFilePath(cfg); got != "/from/env" {
		t.Errorf("the environment must win over config, got %q", got)
	}
}

func TestPassphraseFilePathExpandsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	t.Setenv(envPassphraseFile, "~/.config/secrets/env")
	want := filepath.Join(home, ".config", "secrets", "env")
	if got := passphraseFilePath(Config{}); got != want {
		t.Errorf("passphraseFilePath() = %q, want %q", got, want)
	}
}

// TestPassphraseFromEnvOrFilePrefersEnv keeps an explicitly exported
// TVAULT_PASSPHRASE authoritative, so a shell session is never overridden by a
// stale file.
func TestPassphraseFromEnvOrFilePrefersEnv(t *testing.T) {
	path := writePassphraseFile(t, "TVAULT_PASSPHRASE=from-file\n", 0o600)
	t.Setenv("TVAULT_PASSPHRASE", "from-env")
	t.Setenv(envPassphraseFile, path)

	got, err := passphraseFromEnvOrFile(Config{})
	if err != nil {
		t.Fatalf("passphraseFromEnvOrFile: %v", err)
	}
	if got != "from-env" {
		t.Errorf("passphrase = %q, want the environment value", got)
	}
}

func TestPassphraseFromEnvOrFileFallsBackToFile(t *testing.T) {
	path := writePassphraseFile(t, "TVAULT_PASSPHRASE=from-file\n", 0o600)
	t.Setenv("TVAULT_PASSPHRASE", "")
	t.Setenv(envPassphraseFile, path)

	got, err := passphraseFromEnvOrFile(Config{})
	if err != nil {
		t.Fatalf("passphraseFromEnvOrFile: %v", err)
	}
	if got != "from-file" {
		t.Errorf("passphrase = %q, want the file value", got)
	}
}

func TestPassphraseFromEnvOrFileUnconfiguredIsNotAnError(t *testing.T) {
	t.Setenv("TVAULT_PASSPHRASE", "")
	t.Setenv(envPassphraseFile, "")

	got, err := passphraseFromEnvOrFile(Config{})
	if err != nil {
		t.Fatalf("an unconfigured passphrase source must not error: %v", err)
	}
	if got != "" {
		t.Errorf("passphrase = %q, want empty so the caller can prompt", got)
	}
}
