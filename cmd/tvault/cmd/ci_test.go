package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetCIFlags restores ci init flag vars after a test.
func resetCIFlags(t *testing.T) {
	t.Helper()
	p, m, id, o := ciProvider, ciMode, ciIdentity, ciOutput
	t.Cleanup(func() { ciProvider, ciMode, ciIdentity, ciOutput = p, m, id, o })
}

func TestCIInitGitHubPassphrase(t *testing.T) {
	resetCIFlags(t)
	ciProvider, ciMode, ciOutput = "github-actions", "passphrase", "-"
	out := captureStdout(t, func() {
		if err := runCIInit(nil, nil); err != nil {
			t.Fatalf("ci init: %v", err)
		}
	})
	s := string(out)
	if !strings.Contains(s, "TVAULT_PASSPHRASE") {
		t.Error("passphrase workflow should reference TVAULT_PASSPHRASE")
	}
	if strings.Contains(s, "TVAULT_IDENTITY_KEY") {
		t.Error("passphrase workflow should NOT reference TVAULT_IDENTITY_KEY")
	}
}

func TestCIInitGitHubIdentity(t *testing.T) {
	resetCIFlags(t)
	ciProvider, ciMode, ciIdentity, ciOutput = "github-actions", "identity", "ci", "-"
	out := captureStdout(t, func() {
		if err := runCIInit(nil, nil); err != nil {
			t.Fatalf("ci init: %v", err)
		}
	})
	s := string(out)
	for _, want := range []string{
		"TVAULT_IDENTITY_KEY",
		"if [ -z \"$TVAULT_IDENTITY_KEY\" ]", // fail-fast guard
		"tvault identity export ci --force",  // bootstrap checklist, baked name
		"tvault decrypt-env",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("identity workflow missing %q", want)
		}
	}
	if strings.Contains(s, "TVAULT_PASSPHRASE") {
		t.Error("identity workflow must not reference TVAULT_PASSPHRASE")
	}
}

func TestCIInitGitLabIdentity(t *testing.T) {
	resetCIFlags(t)
	ciProvider, ciMode, ciIdentity, ciOutput = "gitlab", "identity", "deploy", ""
	out := captureStdout(t, func() {
		if err := runCIInit(nil, nil); err != nil {
			t.Fatalf("ci init: %v", err)
		}
	})
	s := string(out)
	if !strings.Contains(s, "TVAULT_IDENTITY_KEY") || !strings.Contains(s, "identity export deploy") {
		t.Errorf("gitlab identity snippet missing expected content:\n%s", s)
	}
}

func TestCIInitInvalidMode(t *testing.T) {
	resetCIFlags(t)
	ciProvider, ciMode = "github-actions", "bogus"
	if err := runCIInit(nil, nil); err == nil {
		t.Fatal("invalid mode should error")
	}
}

func TestCIInitInvalidProvider(t *testing.T) {
	resetCIFlags(t)
	ciProvider, ciMode = "jenkins", "passphrase"
	if err := runCIInit(nil, nil); err == nil {
		t.Fatal("invalid provider should error")
	}
}

func TestCIInitIdentityBadName(t *testing.T) {
	resetCIFlags(t)
	ciProvider, ciMode, ciIdentity = "github-actions", "identity", "../bad"
	if err := runCIInit(nil, nil); err == nil {
		t.Fatal("invalid identity name should error")
	}
}

func TestCIInitWriteToFile(t *testing.T) {
	resetCIFlags(t)
	dest := filepath.Join(t.TempDir(), "nested", "wf.yml") // parent dir must be created
	ciProvider, ciMode, ciOutput = "github-actions", "identity", dest

	if err := runCIInit(nil, nil); err != nil {
		t.Fatalf("ci init: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("workflow file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("workflow file mode = %#o, want 0600", perm)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "TVAULT_IDENTITY_KEY") {
		t.Error("written workflow missing expected content")
	}

	// Refuses to overwrite an existing file.
	if err := runCIInit(nil, nil); err == nil {
		t.Fatal("second ci init should refuse to overwrite the existing file")
	}
}
