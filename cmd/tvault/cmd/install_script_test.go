package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installScriptPath locates scripts/install.sh from this package's directory
// (cmd/tvault/cmd → repo root is three levels up). Skips if sh is unavailable.
func installScriptPath(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	p := filepath.Join("..", "..", "..", "scripts", "install.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("install script not found at %s: %v", p, err)
	}
	return p
}

// runInstallDryRun runs the installer in dry-run mode with the given overrides
// and returns the parsed key=value plan it prints.
func runInstallDryRun(t *testing.T, env map[string]string) map[string]string {
	t.Helper()
	script := installScriptPath(t)

	cmd := exec.CommandContext(context.Background(), "sh", script)
	cmd.Env = append(os.Environ(), "TVAULT_INSTALL_DRY_RUN=1")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh dry-run failed: %v\n%s", err, out)
	}
	plan := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			plan[k] = v
		}
	}
	return plan
}

func TestInstallScript_ResolvesAssetURL(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		wantTag  string
		wantTail string
	}{
		{
			name:     "linux amd64",
			env:      map[string]string{"TVAULT_OS": "linux", "TVAULT_ARCH": "amd64", "TVAULT_VERSION": "0.11.1"},
			wantTag:  "v0.11.1",
			wantTail: "/v0.11.1/tvault_0.11.1_linux_amd64.tar.gz",
		},
		{
			name:     "linux arm64, v-prefixed version normalized",
			env:      map[string]string{"TVAULT_OS": "linux", "TVAULT_ARCH": "arm64", "TVAULT_VERSION": "v0.11.1"},
			wantTag:  "v0.11.1",
			wantTail: "/v0.11.1/tvault_0.11.1_linux_arm64.tar.gz",
		},
		{
			name:     "darwin arm64",
			env:      map[string]string{"TVAULT_OS": "darwin", "TVAULT_ARCH": "arm64", "TVAULT_VERSION": "1.2.3"},
			wantTag:  "v1.2.3",
			wantTail: "/v1.2.3/tvault_1.2.3_darwin_arm64.tar.gz",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := runInstallDryRun(t, c.env)
			if plan["tag"] != c.wantTag {
				t.Errorf("tag = %q, want %q", plan["tag"], c.wantTag)
			}
			if !strings.HasSuffix(plan["url"], c.wantTail) {
				t.Errorf("url = %q, want suffix %q", plan["url"], c.wantTail)
			}
			if !strings.HasSuffix(plan["checksum_url"], c.wantTag+"/checksums.txt") {
				t.Errorf("checksum_url = %q, want .../%s/checksums.txt", plan["checksum_url"], c.wantTag)
			}
		})
	}
}

func TestInstallScript_RespectsInstallDir(t *testing.T) {
	plan := runInstallDryRun(t, map[string]string{
		"TVAULT_OS": "linux", "TVAULT_ARCH": "amd64", "TVAULT_VERSION": "0.11.1",
		"TVAULT_INSTALL_DIR": "/opt/bin",
	})
	if plan["target"] != "/opt/bin/tvault" {
		t.Errorf("target = %q, want /opt/bin/tvault", plan["target"])
	}
}

func TestInstallScript_BaseURLOverride(t *testing.T) {
	plan := runInstallDryRun(t, map[string]string{
		"TVAULT_OS": "linux", "TVAULT_ARCH": "amd64", "TVAULT_VERSION": "0.11.1",
		"TVAULT_BASE_URL": "https://mirror.example.com/dl",
	})
	want := "https://mirror.example.com/dl/v0.11.1/tvault_0.11.1_linux_amd64.tar.gz"
	if plan["url"] != want {
		t.Errorf("url = %q, want %q", plan["url"], want)
	}
}
