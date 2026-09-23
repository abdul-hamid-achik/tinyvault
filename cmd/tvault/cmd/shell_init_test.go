package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hostileValues are values that would execute or corrupt a shell if a loader
// interpolated them unquoted.
var hostileValues = map[string]string{
	"SEMI":     "a;touch PWNED",
	"SUBST":    "$(touch PWNED)",
	"BACKTICK": "`touch PWNED`",
	"QUOTE":    `it's "quoted" \ back`,
	"NEWLINE":  "line1\ntouch PWNED",
	"GLOB":     "*",
	"AMP":      "a&&touch PWNED",
	"PLAIN":    "sk-abc_123.def/+=",
	"EMPTY":    "",
}

func resetShellInitFlags(t *testing.T) {
	t.Helper()
	o, p, a, q := shellInitOnly, shellInitPrefix, shellInitAllowUnlock, shellInitQuiet
	t.Cleanup(func() { shellInitOnly, shellInitPrefix, shellInitAllowUnlock, shellInitQuiet = o, p, a, q })
	shellInitOnly, shellInitPrefix, shellInitAllowUnlock, shellInitQuiet = nil, "", false, false
}

func TestWriteShellAssignmentsSkipsInvalidKeys(t *testing.T) {
	var out, warn bytes.Buffer
	writeShellAssignments(&out, &warn, "zsh", map[string]string{"GOOD": "v", "A;id": "x", "1BAD": "y"})
	if got := out.String(); got != "export GOOD=v\n" {
		t.Errorf("stdout = %q", got)
	}
	if !strings.Contains(warn.String(), `"A;id"`) || !strings.Contains(warn.String(), `"1BAD"`) {
		t.Errorf("invalid keys should be reported by name: %q", warn.String())
	}
}

func TestFishQuote(t *testing.T) {
	if got, want := fishQuote(`it's \x`), `'it\'s \\x'`; got != want {
		t.Errorf("fishQuote = %q, want %q", got, want)
	}
}

// TestShellInitRoundTripsInRealShells evals shell-init output in the real
// shells and checks every hostile value arrives byte-for-byte and nothing runs.
func TestShellInitRoundTripsInRealShells(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish"} {
		t.Run(sh, func(t *testing.T) {
			bin, err := exec.LookPath(sh)
			if err != nil {
				t.Skipf("%s not installed", sh)
			}
			var out, warn bytes.Buffer
			writeShellAssignments(&out, &warn, sh, hostileValues)

			dir := t.TempDir()
			script := filepath.Join(dir, "load")
			if err := os.WriteFile(script, out.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			for key, want := range hostileValues {
				var src string
				if sh == "fish" {
					src = "source " + script + "; printf '%s' \"$" + key + "\""
				} else {
					src = ". " + script + "; printf '%s' \"$" + key + "\""
				}
				c := exec.CommandContext(t.Context(), bin, "-c", src)
				c.Dir = dir
				c.Env = append(os.Environ(), "HOME="+dir)
				got, err := c.Output()
				if err != nil {
					t.Fatalf("%s: eval %s: %v", sh, key, err)
				}
				if string(got) != want {
					t.Errorf("%s: %s = %q, want %q", sh, key, got, want)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "PWNED")); err == nil {
				t.Fatalf("%s: a value executed a command during eval", sh)
			}
		})
	}
}

func TestShellInitRequiresProject(t *testing.T) {
	resetShellInitFlags(t)
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	projectName = ""
	if err := runShellInit(nil, []string{"zsh"}); err == nil {
		t.Fatal("shell-init without --project must fail")
	}
}

// Without an agent and without --allow-unlock, shell-init must stay silent on
// stdout and succeed — even though TVAULT_PASSPHRASE is set — so a login shell
// neither blocks nor unlocks behind the user's back.
func TestShellInitNoAgentIsQuietNoop(t *testing.T) {
	resetShellInitFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	t.Setenv("TVAULT_NO_AGENT", "1")
	setVersionsForCLI(t, vaultPath, "API_KEY", "sk-123")
	projectName = "default"

	var runErr error
	stdout, stderr := captureStdoutErr(t, func() { runErr = runShellInit(nil, []string{"zsh"}) })
	if runErr != nil {
		t.Fatalf("shell-init: %v", runErr)
	}
	if len(stdout) != 0 {
		t.Errorf("stdout must be empty without an agent, got %q", stdout)
	}
	if !strings.Contains(string(stderr), "not loaded") {
		t.Errorf("stderr should explain, got %q", stderr)
	}

	shellInitQuiet = true
	stdout, stderr = captureStdoutErr(t, func() { runErr = runShellInit(nil, []string{"zsh"}) })
	if runErr != nil || len(stdout) != 0 || len(stderr) != 0 {
		t.Errorf("--quiet: err=%v stdout=%q stderr=%q", runErr, stdout, stderr)
	}
}

func TestShellInitAllowUnlockReadsDirectly(t *testing.T) {
	resetShellInitFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	t.Setenv("TVAULT_NO_AGENT", "1")
	setVersionsForCLI(t, vaultPath, "API_KEY", "sk-123")
	setVersionsForCLI(t, vaultPath, "OTHER", "a;b")
	projectName = "default"
	shellInitAllowUnlock = true

	var runErr error
	stdout, _ := captureStdoutErr(t, func() { runErr = runShellInit(nil, []string{"bash"}) })
	if runErr != nil {
		t.Fatalf("shell-init --allow-unlock: %v", runErr)
	}
	if got, want := string(stdout), "export API_KEY=sk-123\nexport OTHER='a;b'\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}

	shellInitOnly = []string{"API_KEY"}
	stdout, _ = captureStdoutErr(t, func() { runErr = runShellInit(nil, []string{"fish"}) })
	if runErr != nil {
		t.Fatal(runErr)
	}
	if got, want := string(stdout), "set -gx API_KEY 'sk-123'\n"; got != want {
		t.Errorf("fish --only stdout = %q, want %q", got, want)
	}
}

func TestShellInitAllowUnlockWithoutSourceIsQuiet(t *testing.T) {
	resetShellInitFlags(t)
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	t.Setenv("TVAULT_NO_AGENT", "1")
	t.Setenv("TVAULT_PASSPHRASE", "")
	t.Setenv(envPassphraseCommand, "")
	t.Setenv(envPassphraseFile, "")
	projectName = "default"
	shellInitAllowUnlock = true

	var runErr error
	stdout, stderr := captureStdoutErr(t, func() { runErr = runShellInit(nil, []string{"zsh"}) })
	if runErr != nil || len(stdout) != 0 {
		t.Fatalf("err=%v stdout=%q", runErr, stdout)
	}
	if !strings.Contains(string(stderr), "locked") {
		t.Errorf("stderr = %q", stderr)
	}
}
