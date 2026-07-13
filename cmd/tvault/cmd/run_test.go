package cmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestRunOnlyPrefixConflictWithNoVault(t *testing.T) {
	oldNoVault, oldOnly, oldPrefix := runEnvNoVault, runOnly, runPrefix
	t.Cleanup(func() { runEnvNoVault, runOnly, runPrefix = oldNoVault, oldOnly, oldPrefix })

	for _, c := range []struct {
		name   string
		only   []string
		prefix string
	}{
		{"only", []string{"DB_URL"}, ""},
		{"prefix", nil, "NUXT_"},
	} {
		t.Run(c.name, func(t *testing.T) {
			runEnvNoVault, runOnly, runPrefix = true, c.only, c.prefix
			// The conflict is checked before any vault access, so a nil cmd and a
			// dummy command argument are enough to reach it.
			err := runRun(nil, []string{"true"})
			if err == nil {
				t.Fatal("expected an error combining --no-vault with --only/--prefix")
			}
			if !strings.Contains(err.Error(), "--no-vault") {
				t.Errorf("error should mention --no-vault, got: %v", err)
			}
		})
	}
}

func TestRunGroupConflictWithNoVault(t *testing.T) {
	oldNoVault, oldGroup, oldEnv := runEnvNoVault, runGroup, runEnvName
	t.Cleanup(func() {
		runEnvNoVault, runGroup, runEnvName = oldNoVault, oldGroup, oldEnv
	})

	runEnvNoVault = true
	runGroup, runEnvName = "webapp", "preview"
	err := runRun(nil, []string{"command-must-not-be-resolved"})
	if err == nil || !strings.Contains(err.Error(), "--group/--env select vault secrets") {
		t.Fatalf("unexpected validation result: %v", err)
	}
}

func TestEnvRejectsIdentityWithGroupBeforeReading(t *testing.T) {
	oldGroup, oldEnv, oldIdentity := envGroupFlag, envEnvFlag, envIdentity
	t.Cleanup(func() {
		envGroupFlag, envEnvFlag, envIdentity = oldGroup, oldEnv, oldIdentity
	})
	envGroupFlag, envEnvFlag = "webapp", "preview"

	t.Run("identity flag", func(t *testing.T) {
		envIdentity = "ci"
		t.Setenv(envIdentityKey, "")
		secrets, err := envSecrets()
		if err == nil || !strings.Contains(err.Error(), "cannot be combined with --identity") {
			t.Fatalf("unexpected validation result: %v", err)
		}
		if secrets != nil {
			t.Fatal("conflicting identity and group flags returned secrets")
		}
	})

	t.Run("identity environment", func(t *testing.T) {
		envIdentity = ""
		t.Setenv(envIdentityKey, "synthetic-identity")
		secrets, err := envSecrets()
		if err == nil || !strings.Contains(err.Error(), envIdentityKey) {
			t.Fatalf("unexpected validation result: %v", err)
		}
		if secrets != nil {
			t.Fatal("conflicting identity environment and group flags returned secrets")
		}
	})
}

func TestSelectSecrets(t *testing.T) {
	all := map[string]string{
		"DIGITALOCEAN_TOKEN": "dop_v1_x",
		"NUXT_DATABASE_URL":  "postgres://db",
		"NUXT_REDIS_URL":     "rediss://r",
		"AWS_REGION":         "us-east-1",
	}

	cases := []struct {
		name        string
		only        []string
		prefix      string
		wantKeys    []string
		wantMissing []string
	}{
		{
			name:     "only allowlist",
			only:     []string{"DIGITALOCEAN_TOKEN", "NUXT_DATABASE_URL"},
			wantKeys: []string{"DIGITALOCEAN_TOKEN", "NUXT_DATABASE_URL"},
		},
		{
			name:     "prefix",
			prefix:   "NUXT_",
			wantKeys: []string{"NUXT_DATABASE_URL", "NUXT_REDIS_URL"},
		},
		{
			name:     "union of only and prefix",
			only:     []string{"DIGITALOCEAN_TOKEN"},
			prefix:   "NUXT_",
			wantKeys: []string{"DIGITALOCEAN_TOKEN", "NUXT_DATABASE_URL", "NUXT_REDIS_URL"},
		},
		{
			name:        "missing only key is reported, not injected",
			only:        []string{"DIGITALOCEAN_TOKEN", "TYPO_KEY"},
			wantKeys:    []string{"DIGITALOCEAN_TOKEN"},
			wantMissing: []string{"TYPO_KEY"},
		},
		{
			name:     "prefix matching nothing yields empty",
			prefix:   "ZZZ_",
			wantKeys: []string{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sel, missing := selectSecrets(all, c.only, c.prefix)

			got := sortedStringKeys(sel)
			if !reflect.DeepEqual(got, sortedCopy(c.wantKeys)) {
				t.Errorf("keys = %v, want %v", got, sortedCopy(c.wantKeys))
			}
			// Values must be preserved verbatim.
			for k := range sel {
				if sel[k] != all[k] {
					t.Errorf("value for %q = %q, want %q", k, sel[k], all[k])
				}
			}
			if !reflect.DeepEqual(missing, c.wantMissing) {
				t.Errorf("missing = %v, want %v", missing, c.wantMissing)
			}
		})
	}
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return sortedCopy(out)
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
