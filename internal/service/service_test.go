package service

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Executable:     "/opt/homebrew/bin/tvault",
		VaultDir:       "/home/u/.tvault",
		PassphraseFile: "/home/u/.config/secrets/env",
		LogDir:         "/home/u/.local/state/tvault",
		LogLevel:       "info",
		Idle:           15 * time.Minute,
	}
}

// TestRenderNeverEmbedsAPassphrase is the security-critical property: a service
// definition may reference the passphrase file's path, never its contents. A
// launchd plist is world-readable by default and lands in backups.
func TestRenderNeverEmbedsAPassphrase(t *testing.T) {
	cfg := testConfig()
	for _, kind := range []Kind{KindLaunchd, KindSystemd} {
		body, err := Render(kind, cfg)
		if err != nil {
			t.Fatalf("%s: Render: %v", kind, err)
		}
		if !strings.Contains(body, cfg.PassphraseFile) {
			t.Errorf("%s: definition should reference the passphrase file path", kind)
		}
		// The passphrase itself can only arrive via the file, so no definition
		// should ever carry an assignment of the variable's value.
		if strings.Contains(body, "TVAULT_PASSPHRASE=") {
			t.Errorf("%s: definition assigns TVAULT_PASSPHRASE directly:\n%s", kind, body)
		}
	}
}

// TestRenderLaunchdProducesValidXML guards against a malformed plist, which
// launchd refuses to load with a famously unhelpful error.
func TestRenderLaunchdProducesValidXML(t *testing.T) {
	body, err := Render(KindLaunchd, testConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var discard any
	if err := xml.Unmarshal([]byte(body), &discard); err != nil {
		t.Fatalf("plist is not well-formed XML: %v\n%s", err, body)
	}
}

// TestRenderLaunchdEscapesXMLMetacharacters covers a home directory containing
// & or <, which would otherwise produce an invalid plist.
func TestRenderLaunchdEscapesXMLMetacharacters(t *testing.T) {
	cfg := testConfig()
	cfg.Executable = `/Users/a&b/bin/tvault`
	cfg.PassphraseFile = `/Users/a&b/<secrets>/env`
	cfg.LogDir = `/Users/a&b/logs`

	body, err := Render(KindLaunchd, cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var discard any
	if err := xml.Unmarshal([]byte(body), &discard); err != nil {
		t.Fatalf("plist with & and < is not well-formed: %v\n%s", err, body)
	}
	if strings.Contains(body, "a&b") && !strings.Contains(body, "a&amp;b") {
		t.Error("ampersand was not escaped")
	}
}

// TestRenderLaunchdDoesNotRestartOnCleanExit keeps the idle auto-lock
// meaningful: restarting after a clean exit would immediately re-derive the KEK
// and hold it in memory again, defeating the timeout.
func TestRenderLaunchdDoesNotRestartOnCleanExit(t *testing.T) {
	body, err := Render(KindLaunchd, testConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(body, "<key>SuccessfulExit</key>") || !strings.Contains(body, "<false/>") {
		t.Errorf("KeepAlive must be gated on SuccessfulExit=false, got:\n%s", body)
	}
}

func TestRenderSystemdShape(t *testing.T) {
	body, err := Render(KindSystemd, testConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"Type=simple", // the agent refuses to daemonize; systemd backgrounds it
		"Restart=on-failure",
		"WantedBy=default.target",
		"Environment=TVAULT_PASSPHRASE_FILE=/home/u/.config/secrets/env",
		"ExecStart=/opt/homebrew/bin/tvault agent start --idle 15m0s",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("unit missing %q, got:\n%s", want, body)
		}
	}
	// Restart=always would undo the idle auto-lock.
	if strings.Contains(body, "Restart=always") {
		t.Error("Restart=always defeats the agent's idle auto-lock")
	}
}

// TestRenderSystemdQuotesPathsWithSpaces guards ExecStart, which systemd splits
// on whitespace: an unquoted path with a space becomes two arguments.
func TestRenderSystemdQuotesPathsWithSpaces(t *testing.T) {
	cfg := testConfig()
	cfg.Executable = "/home/u/my apps/tvault"
	cfg.PassphraseFile = "/home/u/my secrets/env"

	body, err := Render(KindSystemd, cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(body, `ExecStart="/home/u/my apps/tvault"`) {
		t.Errorf("executable with a space must be quoted, got:\n%s", body)
	}
	if !strings.Contains(body, `Environment="TVAULT_PASSPHRASE_FILE=/home/u/my secrets/env"`) {
		t.Errorf("environment value with a space must be quoted, got:\n%s", body)
	}
}

func TestRenderIdleZeroIsPreserved(t *testing.T) {
	cfg := testConfig()
	cfg.Idle = 0
	for _, kind := range []Kind{KindLaunchd, KindSystemd} {
		body, err := Render(kind, cfg)
		if err != nil {
			t.Fatalf("%s: Render: %v", kind, err)
		}
		if !strings.Contains(body, "0s") {
			t.Errorf("%s: --idle 0 (never auto-lock) must reach the definition, got:\n%s", kind, body)
		}
	}
}

func TestRenderOmitsUnsetOptionals(t *testing.T) {
	cfg := Config{
		Executable: "/usr/bin/tvault",
		LogDir:     "/var/log/tvault",
		Idle:       time.Minute,
	}
	body, err := Render(KindSystemd, cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(body, "TVAULT_DIR") {
		t.Error("an unset vault dir must not be baked in, so the definition stays portable")
	}
	if strings.Contains(body, "--log-level") {
		t.Error("an unset log level must not be passed")
	}
}

func TestValidateRejectsRelativePaths(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"executable":      func(c *Config) { c.Executable = "tvault" },
		"vault dir":       func(c *Config) { c.VaultDir = "relative/vault" },
		"passphrase file": func(c *Config) { c.PassphraseFile = "secrets/env" },
		"log dir":         func(c *Config) { c.LogDir = "logs" },
	} {
		cfg := testConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: a relative path must be rejected (a service has no predictable cwd)", name)
		}
	}
}

func TestValidateRequiresExecutable(t *testing.T) {
	cfg := testConfig()
	cfg.Executable = "  "
	if err := cfg.Validate(); err == nil {
		t.Error("an empty executable must be rejected")
	}
}

func TestRenderLaunchdRequiresLogDir(t *testing.T) {
	cfg := testConfig()
	cfg.LogDir = ""
	if _, err := Render(KindLaunchd, cfg); err == nil {
		t.Error("launchd needs a log dir for StandardOutPath/StandardErrorPath")
	}
}

func TestRenderUnknownKind(t *testing.T) {
	if _, err := Render(Kind("upstart"), testConfig()); err == nil {
		t.Error("an unknown service kind must be rejected")
	}
}

func TestUnitPathSystemdHonorsXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/cfg")
	got, err := UnitPath(KindSystemd)
	if err != nil {
		t.Fatalf("UnitPath: %v", err)
	}
	want := filepath.Join("/custom/cfg", "systemd", "user", SystemdUnit)
	if got != want {
		t.Errorf("UnitPath = %q, want %q", got, want)
	}
}

func TestUnitPathSystemdFallsBackToDotConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	got, err := UnitPath(KindSystemd)
	if err != nil {
		t.Fatalf("UnitPath: %v", err)
	}
	want := filepath.Join(home, ".config", "systemd", "user", SystemdUnit)
	if got != want {
		t.Errorf("UnitPath = %q, want %q", got, want)
	}
}

func TestUnitPathLaunchd(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	got, err := UnitPath(KindLaunchd)
	if err != nil {
		t.Fatalf("UnitPath: %v", err)
	}
	want := filepath.Join(home, "Library", "LaunchAgents", LaunchdLabel+".plist")
	if got != want {
		t.Errorf("UnitPath = %q, want %q", got, want)
	}
}

// TestWriteAndRemoveAreIdempotent covers the deploy path: install over an
// existing definition, and uninstall twice.
func TestWriteAndRemoveAreIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	cfg := testConfig()
	first, err := Write(KindSystemd, cfg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != unitPerm {
		t.Errorf("definition perm = %#o, want %#o", perm, unitPerm)
	}

	// Overwriting is how a user picks up an edited config.
	cfg.LogLevel = "debug"
	if _, err := Write(KindSystemd, cfg); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	body, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "--log-level debug") {
		t.Error("re-install did not pick up the changed log level")
	}

	installed, _, err := Installed(KindSystemd)
	if err != nil || !installed {
		t.Fatalf("Installed = %v, %v; want true, nil", installed, err)
	}

	if _, err := Remove(KindSystemd); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Remove(KindSystemd); err != nil {
		t.Errorf("Remove must be idempotent so teardown scripts can run twice, got %v", err)
	}
	installed, _, err = Installed(KindSystemd)
	if err != nil || installed {
		t.Errorf("Installed = %v, %v; want false, nil", installed, err)
	}
}

// TestWriteTightensLoosePreexistingDefinition covers a plist left at launchd's
// default 0644 by an older install.
func TestWriteTightensLoosePreexistingDefinition(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	path, err := UnitPath(KindSystemd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Write(KindSystemd, testConfig()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != unitPerm {
		t.Errorf("perm = %#o, want %#o (a loose pre-existing definition must be tightened)", perm, unitPerm)
	}
}

func TestSystemdQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/bin/tvault":    "/usr/bin/tvault",
		"/my apps/tvault":    `"/my apps/tvault"`,
		`/has"quote/tvault`:  `"/has\"quote/tvault"`,
		`/has\slash/tvault`:  `"/has\\slash/tvault"`,
		"/pct%dir/tvault":    `"/pct%dir/tvault"`,
		"/dollar$dir/tvault": `"/dollar$dir/tvault"`,
		"plain":              "plain",
		"":                   `""`,
	} {
		if got := systemdQuote(in); got != want {
			t.Errorf("systemdQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVerifyProgramCatchesAMissingBinary covers the failure that reports
// success: `launchctl bootstrap` accepts a job whose program is gone, so the
// service looks registered and simply never runs.
func TestVerifyProgramCatchesAMissingBinary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	for _, kind := range []Kind{KindLaunchd, KindSystemd} {
		cfg := testConfig()
		cfg.Executable = filepath.Join(home, "gone", "tvault")
		if _, err := Write(kind, cfg); err != nil {
			t.Fatalf("%s: Write: %v", kind, err)
		}

		exe, err := VerifyProgram(kind)
		if err == nil {
			t.Errorf("%s: a missing binary must be reported, not silently accepted", kind)
		}
		if exe != cfg.Executable {
			t.Errorf("%s: reported program = %q, want %q", kind, exe, cfg.Executable)
		}
		if err != nil && !strings.Contains(err.Error(), "tvault agent install") {
			t.Errorf("%s: the error should say how to fix it, got %v", kind, err)
		}
	}
}

func TestVerifyProgramAcceptsAnExistingBinary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	exe := filepath.Join(home, "tvault")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []Kind{KindLaunchd, KindSystemd} {
		cfg := testConfig()
		cfg.Executable = exe
		if _, err := Write(kind, cfg); err != nil {
			t.Fatalf("%s: Write: %v", kind, err)
		}
		if got, err := VerifyProgram(kind); err != nil || got != exe {
			t.Errorf("%s: VerifyProgram = %q, %v; want %q, nil", kind, got, err, exe)
		}
	}
}

// TestProgramPathRoundTripsEscapedAndQuotedPaths keeps the parser honest for
// the paths that need escaping in each format.
func TestProgramPathRoundTripsEscapedAndQuotedPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	for kind, exe := range map[Kind]string{
		KindLaunchd: "/Users/a&b/bin/tvault",  // & must survive XML escaping
		KindSystemd: "/home/u/my apps/tvault", // a space forces ExecStart quoting
	} {
		cfg := testConfig()
		cfg.Executable = exe
		if _, err := Write(kind, cfg); err != nil {
			t.Fatalf("%s: Write: %v", kind, err)
		}
		got, err := ProgramPath(kind)
		if err != nil {
			t.Fatalf("%s: ProgramPath: %v", kind, err)
		}
		if got != exe {
			t.Errorf("%s: ProgramPath = %q, want %q", kind, got, exe)
		}
	}
}
