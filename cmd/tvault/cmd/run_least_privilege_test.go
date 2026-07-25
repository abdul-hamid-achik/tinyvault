package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func resetRunLeastPrivilegeFlags(t *testing.T) {
	t.Helper()
	oldEnvFile, oldNoVault := runEnvFile, runEnvNoVault
	oldOnly, oldPrefix := runOnly, runPrefix
	oldGroup, oldEnv, oldStrict, oldIdentity := runGroup, runEnvName, runStrict, runIdentity
	runEnvFile, runEnvNoVault = "", false
	runOnly, runPrefix = nil, ""
	runGroup, runEnvName, runStrict, runIdentity = "", "", false, ""
	t.Cleanup(func() {
		runEnvFile, runEnvNoVault = oldEnvFile, oldNoVault
		runOnly, runPrefix = oldOnly, oldPrefix
		runGroup, runEnvName, runStrict, runIdentity = oldGroup, oldEnv, oldStrict, oldIdentity
	})
}

func runEnvOutput(t *testing.T) string {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	output := captureStdout(t, func() {
		if err := runRun(cmd, []string{"sh", "-c", `printf '%s|%s|%s|%s' "$CHALUPA_TOKEN" "$UNRELATED_SECRET" "${TVAULT_PASSPHRASE-unset}" "${TVAULT_DIR-unset}"`}); err != nil {
			t.Fatalf("runRun: %v", err)
		}
	})
	return string(output)
}

func TestRunSelectedDirectInjectsNoUnrelatedVaultOrControlValues(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	resetRunLeastPrivilegeFlags(t)

	v := openTestVault(t, vaultPath)
	for key, value := range map[string]string{
		"CHALUPA_TOKEN":    "selected",
		"UNRELATED_SECRET": "must-not-reach-child",
	} {
		if err := v.SetSecret("default", key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	runOnly, runStrict = []string{"CHALUPA_TOKEN"}, true
	t.Setenv("TVAULT_DIR", vaultPath)
	if got := runEnvOutput(t); got != "selected||unset|unset" {
		t.Fatal("child did not receive only the selected value and no TinyVault controls")
	}
}

func TestRunSelectedGroupHonorsInheritanceWithoutInjectingUnselectedValues(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	resetRunLeastPrivilegeFlags(t)

	v := openTestVault(t, vaultPath)
	if _, err := v.CreateProject("base", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CreateProject("preview", ""); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("base", "CHALUPA_TOKEN", "inherited"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("base", "UNRELATED_SECRET", "base-unrelated"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CreateEnvGroup("app", "", []ivault.EnvGroupEntry{
		{Name: "base", Project: "base"},
		{Name: "preview", Project: "preview"},
	}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := v.SetInheritance("app", "preview", "base"); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	runGroup, runEnvName = "app", "preview"
	runPrefix = "CHALUPA_"
	if got := runEnvOutput(t); got != "inherited||unset|unset" {
		t.Fatal("group selection did not inject only the inherited selected value")
	}
}

func TestRunIdentitySelectedReadAndStrictMissing(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	resetRunLeastPrivilegeFlags(t)
	t.Setenv(envIdentityKey, "")

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "CHALUPA_TOKEN", "identity-selected"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "UNRELATED_SECRET", "identity-unrelated"); err != nil {
		t.Fatal(err)
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ShareProject("default", id.Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	writeTestIdentity(t, "ci", id)

	runIdentity, runOnly, runStrict = "ci", []string{"CHALUPA_TOKEN"}, true
	t.Setenv("TVAULT_PASSPHRASE", "")
	if got := runEnvOutput(t); got != "identity-selected||unset|unset" {
		t.Fatal("identity selection did not inject only the selected value")
	}

	runOnly = []string{"MISSING"}
	err = runRun(&cobra.Command{}, []string{"sh", "-c", "exit 0"})
	if err == nil || !strings.Contains(err.Error(), "--only key(s) not found") {
		t.Fatalf("identity strict missing = %v, want strict missing-key error", err)
	}
}

func TestRunIdentityGroupSelectedReadAndStrictMissing(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	resetRunLeastPrivilegeFlags(t)

	v := openTestVault(t, vaultPath)
	if _, err := v.CreateProject("base", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CreateProject("preview", ""); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("base", "CHALUPA_TOKEN", "inherited-identity"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("base", "UNRELATED_SECRET", "base-unrelated"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("preview", "UNRELATED_SECRET", "preview-unrelated"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CreateEnvGroup("app", "", []ivault.EnvGroupEntry{
		{Name: "base", Project: "base"},
		{Name: "preview", Project: "preview"},
	}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := v.SetInheritance("app", "preview", "base"); err != nil {
		t.Fatal(err)
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"base", "preview"} {
		if err := v.ShareProject(project, id.Recipient()); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	writeTestIdentity(t, "ci", id)

	runIdentity, runGroup, runEnvName, runPrefix = "ci", "app", "preview", "CHALUPA_"
	t.Setenv("TVAULT_PASSPHRASE", "")
	if got := runEnvOutput(t); got != "inherited-identity||unset|unset" {
		t.Fatalf("identity group selection = %q", got)
	}

	runOnly, runPrefix, runStrict = []string{"MISSING"}, "", true
	marker := filepath.Join(t.TempDir(), "target-ran")
	err = runRun(&cobra.Command{}, []string{"touch", marker})
	if err == nil || !strings.Contains(err.Error(), "--only key(s) not found") {
		t.Fatalf("identity/group strict missing = %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("identity/group strict missing launched the child process")
	}
}
