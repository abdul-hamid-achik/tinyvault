package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// isolatePassphraseSources points every passphrase and config lookup at an
// empty temporary HOME with the default vault location, so a test sees only
// the sources it creates — never the operator's real ~/.config/secrets/env,
// config.yaml, or passphrase command.
func isolatePassphraseSources(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	prevVault, prevCfg := vaultDir, cfgFile
	vaultDir, cfgFile = "", ""
	t.Cleanup(func() { vaultDir, cfgFile = prevVault, prevCfg })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, k := range []string{"TVAULT_DIR", "TVAULT_PASSPHRASE", envPassphraseCommand, envPassphraseFile, envConfigFile, "XDG_CONFIG_HOME"} {
		t.Setenv(k, "")
	}
	return home
}

func writeFileMode(t *testing.T, path, body string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // defeat the umask
		t.Fatal(err)
	}
	return path
}

// writeHelper writes an executable /bin/sh script and returns its path.
func writeHelper(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell helper scripts need a POSIX shell")
	}
	return writeFileMode(t, filepath.Join(t.TempDir(), "helper.sh"), "#!/bin/sh\n"+body+"\n", 0o700)
}

func TestSplitCommandLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"op read op://Private/tvault/password", []string{"op", "read", "op://Private/tvault/password"}},
		{"  security  find-generic-password -s tvault -w ", []string{"security", "find-generic-password", "-s", "tvault", "-w"}},
		{`op read "op://My Vault/tvault/password"`, []string{"op", "read", "op://My Vault/tvault/password"}},
		{`pass show 'tvault/main pass'`, []string{"pass", "show", "tvault/main pass"}},
		{`echo "a\"b" c\ d`, []string{"echo", `a"b`, "c d"}},
		{`echo '' x`, []string{"echo", "", "x"}},
		// No shell semantics: these are literal arguments, not expansions.
		{`echo $HOME $(id) ; rm`, []string{"echo", "$HOME", "$(id)", ";", "rm"}},
	}
	for _, c := range cases {
		got, err := splitCommandLine(c.in)
		if err != nil {
			t.Errorf("splitCommandLine(%q): %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitCommandLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", "   ", `op "unterminated`, `op 'x`, `op x\`} {
		if _, err := splitCommandLine(bad); err == nil {
			t.Errorf("splitCommandLine(%q) should fail", bad)
		}
	}
}

func TestCommandSpecYAML(t *testing.T) {
	var list Config
	if err := yaml.Unmarshal([]byte("agent:\n  passphrase_command: [\"op\", \"read\", \"op://a b/c\"]\n"), &list); err != nil {
		t.Fatal(err)
	}
	if want := []string{"op", "read", "op://a b/c"}; !reflect.DeepEqual([]string(list.Agent.PassphraseCommand), want) {
		t.Errorf("list form = %q, want %q", list.Agent.PassphraseCommand, want)
	}
	var str Config
	if err := yaml.Unmarshal([]byte("agent:\n  passphrase_command: security find-generic-password -s tvault -w\n"), &str); err != nil {
		t.Fatal(err)
	}
	if want := []string{"security", "find-generic-password", "-s", "tvault", "-w"}; !reflect.DeepEqual([]string(str.Agent.PassphraseCommand), want) {
		t.Errorf("string form = %q, want %q", str.Agent.PassphraseCommand, want)
	}
	var bad Config
	if err := yaml.Unmarshal([]byte("agent:\n  passphrase_command: {a: b}\n"), &bad); err == nil {
		t.Error("a mapping must be rejected")
	}
}

func TestRunPassphraseCommandTrimsNewline(t *testing.T) {
	helper := writeHelper(t, `printf 'hunter2 with space\r\n'`)
	got, err := runPassphraseCommand([]string{helper}, "test")
	if err != nil {
		t.Fatalf("runPassphraseCommand: %v", err)
	}
	if got != "hunter2 with space" {
		t.Errorf("passphrase = %q, want trailing CRLF trimmed only", got)
	}
}

func TestRunPassphraseCommandFailureNeverLeaksStdout(t *testing.T) {
	helper := writeHelper(t, `printf 'SECRET-PARTIAL'; exit 3`)
	_, err := runPassphraseCommand([]string{helper}, "test")
	if err == nil {
		t.Fatal("a failing helper must be an error")
	}
	if strings.Contains(err.Error(), "SECRET-PARTIAL") {
		t.Fatalf("error leaks helper stdout: %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("error should name the exit status: %v", err)
	}
}

func TestRunPassphraseCommandRejectsEmptyAndHuge(t *testing.T) {
	if _, err := runPassphraseCommand([]string{writeHelper(t, `printf '\n'`)}, "test"); err == nil {
		t.Error("empty output must be rejected")
	}
	huge := writeHelper(t, `i=0; while [ $i -lt 2000 ]; do printf 'xxxxxxxx'; i=$((i+1)); done`)
	_, err := runPassphraseCommand([]string{huge}, "test")
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("oversized output must be rejected, got %v", err)
	}
}

func TestRunPassphraseCommandGetsNoStdin(t *testing.T) {
	// Under `tvault mcp`, stdin is the protocol stream; the helper must see EOF.
	helper := writeHelper(t, `if read -r line; then printf 'read-stdin'; else printf 'no-stdin'; fi`)
	got, err := runPassphraseCommand([]string{helper}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got != "no-stdin" {
		t.Errorf("helper read from stdin: %q", got)
	}
}

func TestPassphrasePrecedence(t *testing.T) {
	home := isolatePassphraseSources(t)
	cmdHelper := writeHelper(t, `printf 'from-env-command'`)
	cfgHelper := writeHelper(t, `printf 'from-config-command'`)
	envFile := writeFileMode(t, filepath.Join(t.TempDir(), "pass.env"), "TVAULT_PASSPHRASE=from-env-file\n", 0o600)
	cfgFileP := writeFileMode(t, filepath.Join(t.TempDir(), "cfg.env"), "TVAULT_PASSPHRASE=from-config-file\n", 0o600)
	writeFileMode(t, filepath.Join(home, ".config", "secrets", "env"), "export TVAULT_PASSPHRASE=from-implicit\n", 0o600)
	writeFileMode(t, filepath.Join(home, defaultVaultDir, "config.yaml"),
		"agent:\n  passphrase_command: ["+`"`+cfgHelper+`"`+"]\n  passphrase_file: "+cfgFileP+"\n", 0o600)

	check := func(want string) {
		t.Helper()
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		got, err := nonInteractivePassphrase(cfg)
		if err != nil {
			t.Fatalf("nonInteractivePassphrase: %v", err)
		}
		if got != want {
			t.Errorf("passphrase = %q, want %q", got, want)
		}
	}

	t.Setenv("TVAULT_PASSPHRASE", "from-env")
	t.Setenv(envPassphraseCommand, cmdHelper)
	t.Setenv(envPassphraseFile, envFile)
	check("from-env")
	t.Setenv("TVAULT_PASSPHRASE", "")
	check("from-env-command")
	t.Setenv(envPassphraseCommand, "")
	check("from-env-file") // an explicit env file beats a config command
	t.Setenv(envPassphraseFile, "")
	check("from-config-command") // a config command beats every file, incl. the implicit one

	writeFileMode(t, filepath.Join(home, defaultVaultDir, "config.yaml"), "agent:\n  passphrase_file: "+cfgFileP+"\n", 0o600)
	check("from-config-file")
	if err := os.Remove(filepath.Join(home, defaultVaultDir, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	check("from-implicit")
}

// TestImplicitFileWithoutPassphraseIsNotAnError pins the migration path: once
// TVAULT_PASSPHRASE moves out of ~/.config/secrets/env (and the file instead
// evals `tvault shell-init`), the file must stop being an unlock source rather
// than become a hard error for every non-interactive command.
func TestImplicitFileWithoutPassphraseIsNotAnError(t *testing.T) {
	home := isolatePassphraseSources(t)
	writeFileMode(t, filepath.Join(home, ".config", "secrets", "env"),
		"export EDITOR=nvim\neval \"$(tvault shell-init zsh --project personal --quiet)\"\n", 0o600)

	got, err := nonInteractivePassphrase(Config{})
	if err != nil {
		t.Fatalf("an implicit file without TVAULT_PASSPHRASE must not error: %v", err)
	}
	if got != "" {
		t.Errorf("passphrase = %q, want empty (prompt / fail closed)", got)
	}
	if src := passphraseSource(Config{}); src != "" {
		t.Errorf("passphraseSource = %q, want none", src)
	}
}

// An explicitly named file is still strict: a typo must not silently prompt.
func TestExplicitFileWithoutPassphraseIsAnError(t *testing.T) {
	isolatePassphraseSources(t)
	path := writeFileMode(t, filepath.Join(t.TempDir(), "env"), "export EDITOR=nvim\n", 0o600)
	t.Setenv(envPassphraseFile, path)
	if _, err := nonInteractivePassphrase(Config{}); err == nil {
		t.Fatal("an explicit file without TVAULT_PASSPHRASE must be an error")
	}
}

func TestPassphraseCommandFromUntrustedConfigIsRefused(t *testing.T) {
	home := isolatePassphraseSources(t)
	marker := filepath.Join(t.TempDir(), "ran")
	helper := writeHelper(t, "touch '"+marker+"'; printf x")
	cfgPath := writeFileMode(t, filepath.Join(home, defaultVaultDir, "config.yaml"),
		"agent:\n  passphrase_command: [\""+helper+"\"]\n", 0o666)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	_, err = nonInteractivePassphrase(cfg)
	if err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("a group/world-writable config must not run its command, got %v", err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("the helper ran from an untrusted config")
	}

	if err := os.Chmod(cfgPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := nonInteractivePassphrase(cfg); err != nil || got != "x" {
		t.Fatalf("a 0600 config should run its command: %q, %v", got, err)
	}
}

// passphraseSource is consulted on hot, non-unlocking paths (MCP startup,
// agent start, doctor) and must never run the helper — it may prompt for
// Touch ID.
func TestPassphraseSourceDoesNotRunCommand(t *testing.T) {
	isolatePassphraseSources(t)
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv(envPassphraseCommand, writeHelper(t, "touch '"+marker+"'; printf x"))
	if got := passphraseSource(Config{}); got != passSourceCommand {
		t.Errorf("passphraseSource = %q, want command", got)
	}
	if mcpHasPassphrase() {
		t.Error("MCP must prefer a running agent over a passphrase command")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("passphraseSource / mcpHasPassphrase ran the helper")
	}
}

func TestConfigPathResolution(t *testing.T) {
	home := isolatePassphraseSources(t)
	vaultCfg := filepath.Join(home, defaultVaultDir, "config.yaml")
	xdgCfg := filepath.Join(home, ".config", "tvault", "config.yaml")

	if got := configPath(); got != vaultCfg {
		t.Errorf("no config anywhere: got %q, want the vault-dir default %q", got, vaultCfg)
	}
	writeFileMode(t, xdgCfg, "agent: {}\n", 0o600)
	if got := configPath(); got != xdgCfg {
		t.Errorf("only XDG config: got %q, want %q", got, xdgCfg)
	}
	custom := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("XDG_CONFIG_HOME", custom)
	writeFileMode(t, filepath.Join(custom, "tvault", "config.yaml"), "agent: {}\n", 0o600)
	if got, want := configPath(), filepath.Join(custom, "tvault", "config.yaml"); got != want {
		t.Errorf("XDG_CONFIG_HOME: got %q, want %q", got, want)
	}
	writeFileMode(t, vaultCfg, "agent: {}\n", 0o600)
	if got := configPath(); got != vaultCfg {
		t.Errorf("both exist: got %q, want the vault-dir config %q", got, vaultCfg)
	}
	explicit := writeFileMode(t, filepath.Join(t.TempDir(), "c.yaml"), "agent: {}\n", 0o600)
	t.Setenv(envConfigFile, explicit)
	if got := configPath(); got != explicit {
		t.Errorf("TVAULT_CONFIG: got %q, want %q", got, explicit)
	}
}

// A scratch vault must never pick up the operator's XDG config (and so their
// passphrase command).
func TestConfigPathScratchVaultIgnoresXDG(t *testing.T) {
	home := isolatePassphraseSources(t)
	writeFileMode(t, filepath.Join(home, ".config", "tvault", "config.yaml"), "agent: {}\n", 0o600)
	scratch := t.TempDir()
	t.Setenv("TVAULT_DIR", scratch)
	if got, want := configPath(), filepath.Join(scratch, "config.yaml"); got != want {
		t.Errorf("scratch vault: got %q, want %q", got, want)
	}
}
