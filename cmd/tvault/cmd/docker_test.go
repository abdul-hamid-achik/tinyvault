package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDockerArgvBuildSecretsNotOnCommandLine(t *testing.T) {
	argv := dockerArgv("build", map[string]string{"Z_KEY": "zval", "API_KEY": "sk_never_on_argv"}, []string{"-t", "app", "."})
	got := strings.Join(argv, "\n")
	if strings.Contains(got, "sk_never_on_argv") || strings.Contains(got, "zval") {
		t.Fatalf("value leaked onto argv:\n%s", got)
	}
	want := []string{"build", "--secret", "id=API_KEY,env=API_KEY", "--secret", "id=Z_KEY,env=Z_KEY", "-t", "app", "."}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
}

func TestDockerArgvRunNameOnly(t *testing.T) {
	argv := dockerArgv("run", map[string]string{"API_KEY": "secret"}, []string{"--rm", "alpine", "env"})
	got := strings.Join(argv, " ")
	if strings.Contains(got, "secret") {
		t.Fatalf("value leaked onto argv: %s", got)
	}
	if strings.Join(argv, " ") != "run -e API_KEY --rm alpine env" {
		t.Fatalf("argv = %v", argv)
	}
}

func TestDockerArgvComposeNoDashE(t *testing.T) {
	argv := dockerArgv("compose", map[string]string{"API_KEY": "secret"}, []string{"up", "-d"})
	if strings.Join(argv, " ") != "compose up -d" {
		t.Fatalf("argv = %v", argv)
	}
}

func TestDockerInitSnippets(t *testing.T) {
	body := dockerInitSnippets()
	for _, want := range []string{
		"RUN --mount=type=secret,id=NPM_TOKEN",
		"DATABASE_URL: ${DATABASE_URL}",
		"tvault docker build",
		"environment: NPM_TOKEN",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("init snippet missing %q", want)
		}
	}
}

func TestRunDockerInit(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runDockerInit(nil, nil); err != nil {
			t.Fatalf("runDockerInit: %v", err)
		}
	})
	if !strings.Contains(string(out), "RUN --mount=type=secret") {
		t.Fatalf("init stdout missing Dockerfile snippet:\n%s", out)
	}
}

func TestRunDockerStrictMissingOnlyKey(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	oldOnly, oldStrict := dockerOnly, dockerStrict
	dockerOnly, dockerStrict = []string{"MISSING"}, true
	t.Cleanup(func() { dockerOnly, dockerStrict = oldOnly, oldStrict })

	err := runDockerBuild(nil, []string{"."})
	if err == nil || !strings.Contains(err.Error(), "--only key(s) not found") {
		t.Fatalf("runDockerBuild() error = %v, want missing-key", err)
	}
}

func TestRunDockerNotFound(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	t.Setenv("PATH", t.TempDir())
	err := runDockerBuild(nil, []string{"."})
	if err == nil || !strings.Contains(err.Error(), "docker not found") {
		t.Fatalf("runDockerBuild() error = %v, want docker-not-found", err)
	}
}

func TestRunDockerBuildInjectsBuildKitSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shim is a POSIX script")
	}
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "API_KEY", "sk_never_on_argv"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	binDir := t.TempDir()
	argvFile := filepath.Join(t.TempDir(), "argv")
	apiFile := filepath.Join(t.TempDir(), "api")
	passFile := filepath.Join(t.TempDir(), "pass")
	bkFile := filepath.Join(t.TempDir(), "bk")
	shim := filepath.Join(binDir, "docker")
	body := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$TV_TEST_DOCKER_ARGV\"\n" +
		"printf '%s\\n' \"$API_KEY\" > \"$TV_TEST_DOCKER_API\"\n" +
		"printf '%s\\n' \"${TVAULT_PASSPHRASE-}\" > \"$TV_TEST_DOCKER_PASS\"\n" +
		"printf '%s\\n' \"${DOCKER_BUILDKIT-}\" > \"$TV_TEST_DOCKER_BK\"\n"
	if err := os.WriteFile(shim, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TV_TEST_DOCKER_ARGV", argvFile)
	t.Setenv("TV_TEST_DOCKER_API", apiFile)
	t.Setenv("TV_TEST_DOCKER_PASS", passFile)
	t.Setenv("TV_TEST_DOCKER_BK", bkFile)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	reset := stashDockerFlags(t)
	defer reset()

	if err := runDockerBuild(nil, []string{"-t", "app", "."}); err != nil {
		t.Fatalf("runDockerBuild: %v", err)
	}

	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	argvBody := string(argv)
	if strings.Contains(argvBody, "sk_never_on_argv") {
		t.Fatalf("secret leaked onto docker argv:\n%s", argvBody)
	}
	for _, want := range []string{"build\n", "--secret\n", "id=API_KEY,env=API_KEY\n", "-t\n", "app\n", ".\n"} {
		if !strings.Contains(argvBody, want) {
			t.Errorf("argv missing %q:\n%s", want, argvBody)
		}
	}

	api, err := os.ReadFile(apiFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(api)) != "sk_never_on_argv" {
		t.Errorf("docker env API_KEY = %q", api)
	}
	pass, err := os.ReadFile(passFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(pass)) != "" {
		t.Errorf("TVAULT_PASSPHRASE leaked into docker env: %q", pass)
	}
	bk, err := os.ReadFile(bkFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(bk)) != "1" {
		t.Errorf("DOCKER_BUILDKIT = %q, want 1", bk)
	}
}

func TestRunDockerComposeAndRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shim is a POSIX script")
	}
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "API_KEY", "sk_never_on_argv"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	binDir := t.TempDir()
	argvFile := filepath.Join(t.TempDir(), "argv")
	shim := filepath.Join(binDir, "docker")
	body := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$TV_TEST_DOCKER_ARGV\"\n"
	if err := os.WriteFile(shim, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TV_TEST_DOCKER_ARGV", argvFile)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	reset := stashDockerFlags(t)
	defer reset()

	if err := runDockerCompose(nil, []string{"up", "-d"}); err != nil {
		t.Fatalf("compose: %v", err)
	}
	composeArgv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(composeArgv); got != "compose\nup\n-d\n" {
		t.Errorf("compose argv:\n%s", got)
	}
	if strings.Contains(string(composeArgv), "sk_never_on_argv") {
		t.Fatal("compose argv leaked a value")
	}

	if err := runDockerRun(nil, []string{"--rm", "alpine", "env"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	runArgv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(runArgv); got != "run\n-e\nAPI_KEY\n--rm\nalpine\nenv\n" {
		t.Errorf("run argv:\n%s", got)
	}
	if strings.Contains(string(runArgv), "sk_never_on_argv") {
		t.Fatal("run argv leaked a value")
	}
}

func stashDockerFlags(t *testing.T) func() {
	t.Helper()
	oldOnly, oldPrefix, oldIdent, oldGroup, oldEnv, oldStrict := dockerOnly, dockerPrefix, dockerIdentity, dockerGroup, dockerEnvName, dockerStrict
	dockerOnly, dockerPrefix, dockerIdentity, dockerGroup, dockerEnvName, dockerStrict = nil, "", "", "", "", false
	return func() {
		dockerOnly, dockerPrefix, dockerIdentity, dockerGroup, dockerEnvName, dockerStrict = oldOnly, oldPrefix, oldIdent, oldGroup, oldEnv, oldStrict
	}
}
