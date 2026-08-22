package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuildSSHInjectScript(t *testing.T) {
	got := buildSSHInjectScript(map[string]string{
		"Z_LAST":  "z",
		"A_FIRST": "a",
		"QUOTE":   `it's "quoted"`,
	})
	if !strings.HasPrefix(got, "set -e\n") {
		t.Fatalf("missing set -e:\n%s", got)
	}
	if !strings.HasSuffix(got, "exec \"$@\"\n") {
		t.Fatalf("missing exec:\n%s", got)
	}
	// Keys sorted; quoted value uses the same POSIX quoting as tvault env.
	if !strings.Contains(got, "export A_FIRST=a\n") {
		t.Errorf("A_FIRST:\n%s", got)
	}
	if !strings.Contains(got, "export QUOTE="+escapeShellValue(`it's "quoted"`)+"\n") {
		t.Errorf("QUOTE quoting:\n%s", got)
	}
	idxA := strings.Index(got, "export A_FIRST=")
	idxQ := strings.Index(got, "export QUOTE=")
	idxZ := strings.Index(got, "export Z_LAST=")
	if idxA < 0 || idxQ < 0 || idxZ < 0 || !(idxA < idxQ && idxQ < idxZ) {
		t.Errorf("export order: A=%d Q=%d Z=%d\n%s", idxA, idxQ, idxZ, got)
	}
}

func TestRunSSHRequiresDestinationAndCommand(t *testing.T) {
	if err := runSSH(nil, nil); err == nil || !strings.Contains(err.Error(), "destination and command") {
		t.Fatalf("empty args: %v", err)
	}
	if err := runSSH(nil, []string{"host"}); err == nil || !strings.Contains(err.Error(), "destination and command") {
		t.Fatalf("dest only: %v", err)
	}
}

func TestRunSSHInjectsSecretsOverStdinNotArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake ssh shim is a POSIX script")
	}
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "API_KEY", "sk_never_on_argv"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "WITH_QUOTE", `o'reilly`); err != nil {
		t.Fatal(err)
	}
	v.Close()

	binDir := t.TempDir()
	argvFile := filepath.Join(t.TempDir(), "argv")
	stdinFile := filepath.Join(t.TempDir(), "stdin")
	shim := filepath.Join(binDir, "ssh")
	body := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$TVAULT_TEST_SSH_ARGV\"\n" +
		"cat > \"$TVAULT_TEST_SSH_STDIN\"\n"
	if err := os.WriteFile(shim, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TVAULT_TEST_SSH_ARGV", argvFile)
	t.Setenv("TVAULT_TEST_SSH_STDIN", stdinFile)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	oldOnly, oldPrefix, oldIdent, oldGroup, oldEnv, oldStrict, oldArgs := sshOnly, sshPrefix, sshIdentity, sshGroup, sshEnvName, sshStrict, sshArgs
	sshOnly, sshPrefix, sshIdentity, sshGroup, sshEnvName, sshStrict, sshArgs = nil, "", "", "", "", false, []string{"-p", "2222"}
	t.Cleanup(func() {
		sshOnly, sshPrefix, sshIdentity, sshGroup, sshEnvName, sshStrict, sshArgs = oldOnly, oldPrefix, oldIdent, oldGroup, oldEnv, oldStrict, oldArgs
	})

	if err := runSSH(nil, []string{"deploy@prod", "systemctl", "restart", "api"}); err != nil {
		t.Fatalf("runSSH: %v", err)
	}

	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	argvBody := string(argv)
	if strings.Contains(argvBody, "sk_never_on_argv") || strings.Contains(argvBody, "o'reilly") {
		t.Fatalf("secret leaked onto ssh argv:\n%s", argvBody)
	}
	for _, want := range []string{"-p\n", "2222\n", "deploy@prod\n", "sh\n", "-s\n", "--\n", "systemctl\n", "restart\n", "api\n"} {
		if !strings.Contains(argvBody, want) {
			t.Errorf("argv missing %q:\n%s", want, argvBody)
		}
	}

	stdin, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatal(err)
	}
	script := string(stdin)
	if !strings.Contains(script, "export API_KEY=sk_never_on_argv\n") {
		t.Errorf("stdin missing API_KEY export:\n%s", script)
	}
	if !strings.Contains(script, "export WITH_QUOTE="+escapeShellValue(`o'reilly`)+"\n") {
		t.Errorf("stdin missing quoted value:\n%s", script)
	}
	if !strings.Contains(script, "exec \"$@\"\n") {
		t.Errorf("stdin missing exec:\n%s", script)
	}
}

func TestRunSSHStrictMissingOnlyKey(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	oldOnly, oldStrict := sshOnly, sshStrict
	sshOnly, sshStrict = []string{"MISSING"}, true
	t.Cleanup(func() { sshOnly, sshStrict = oldOnly, oldStrict })

	err := runSSH(nil, []string{"host", "true"})
	if err == nil || !strings.Contains(err.Error(), "--only key(s) not found") {
		t.Fatalf("runSSH() error = %v, want missing-key error", err)
	}
}

func TestRunSSHSSHNotFound(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	t.Setenv("PATH", t.TempDir())
	err := runSSH(nil, []string{"host", "true"})
	if err == nil || !strings.Contains(err.Error(), "ssh not found") {
		t.Fatalf("runSSH() error = %v, want ssh-not-found", err)
	}
}
