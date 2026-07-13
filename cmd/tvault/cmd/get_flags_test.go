package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type getFlagTestCase struct {
	from       string
	version    int
	group      string
	env        string
	showSource bool
}

func setGetFlagTestCase(t *testing.T, tc getFlagTestCase) {
	t.Helper()

	oldFrom, oldVersion := getFromFile, getVersion
	oldGroup, oldEnv, oldShowSource := getGroup, getEnv, getShowSource
	getFromFile, getVersion = tc.from, tc.version
	getGroup, getEnv, getShowSource = tc.group, tc.env, tc.showSource
	t.Cleanup(func() {
		getFromFile, getVersion = oldFrom, oldVersion
		getGroup, getEnv, getShowSource = oldGroup, oldEnv, oldShowSource
	})
}

func TestValidateGetFlagsAcceptsOnlyOneSourceMode(t *testing.T) {
	for mask := 0; mask < 32; mask++ {
		fromSet := mask&(1<<0) != 0
		versionSet := mask&(1<<1) != 0
		groupSet := mask&(1<<2) != 0
		envSet := mask&(1<<3) != 0
		showSource := mask&(1<<4) != 0

		tc := getFlagTestCase{showSource: showSource}
		if fromSet {
			tc.from = ".env"
		}
		if versionSet {
			tc.version = 1
		}
		if groupSet {
			tc.group = "webapp"
		}
		if envSet {
			tc.env = "preview"
		}

		// The five valid combinations are: current project, dotenv file,
		// historical version, group+env, and group+env+show-source.
		wantValid := mask == 0 || mask == 1 || mask == 2 || mask == 12 || mask == 28
		name := fmt.Sprintf("F%t_V%t_G%t_E%t_S%t", fromSet, versionSet, groupSet, envSet, showSource)
		t.Run(name, func(t *testing.T) {
			setGetFlagTestCase(t, tc)
			err := validateGetFlags()
			if wantValid && err != nil {
				t.Fatalf("valid flag mode rejected: %v", err)
			}
			if !wantValid && err == nil {
				t.Fatal("ambiguous flag mode accepted")
			}
		})
	}
}

func TestGetRejectsAmbiguousFlagsBeforeReading(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("K=synthetic-file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		flags getFlagTestCase
		want  string
	}{
		"group without environment": {
			flags: getFlagTestCase{group: "webapp"},
			want:  "--group and --env must be used together",
		},
		"environment without group": {
			flags: getFlagTestCase{env: "preview"},
			want:  "--group and --env must be used together",
		},
		"negative version": {
			flags: getFlagTestCase{version: -1},
			want:  "--version cannot be negative",
		},
		"dotenv with version": {
			flags: getFlagTestCase{from: envFile, version: 1},
			want:  "--from and --version are mutually exclusive",
		},
		"dotenv with group": {
			flags: getFlagTestCase{from: envFile, group: "webapp", env: "preview"},
			want:  "--from and --group/--env are mutually exclusive",
		},
		"dotenv with source metadata": {
			flags: getFlagTestCase{from: envFile, showSource: true},
			want:  "--from and --show-source are mutually exclusive",
		},
		"version with group": {
			flags: getFlagTestCase{version: 1, group: "webapp", env: "preview"},
			want:  "--version is not supported with --group/--env",
		},
		"version with source metadata": {
			flags: getFlagTestCase{version: 1, showSource: true},
			want:  "--version and --show-source are mutually exclusive",
		},
		"source metadata without group": {
			flags: getFlagTestCase{showSource: true},
			want:  "--show-source requires --group and --env",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			setGetFlagTestCase(t, tc.flags)

			oldVaultDir, oldNoAgent := vaultDir, noAgent
			vaultDir = filepath.Join(t.TempDir(), "missing-vault")
			noAgent = true
			t.Cleanup(func() {
				vaultDir, noAgent = oldVaultDir, oldNoAgent
			})

			var getErr error
			stdout, stderr := captureStdoutErr(t, func() {
				getErr = runGet(nil, []string{"K"})
			})
			if getErr == nil {
				t.Fatal("ambiguous flags unexpectedly succeeded")
			}
			if !strings.Contains(getErr.Error(), tc.want) {
				t.Fatalf("unexpected validation error: %v", getErr)
			}
			if len(stdout) != 0 {
				t.Fatalf("ambiguous flags emitted %d bytes", len(stdout))
			}
			if len(stderr) != 0 {
				t.Fatalf("ambiguous flags emitted %d stderr bytes", len(stderr))
			}
		})
	}
}
