package cmd

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// setupVaultForCommandTest creates a fresh vault in t.TempDir, sets
// vaultDir + TVAULT_PASSPHRASE, and returns the vault path plus a
// restore func. It is a sibling of setupImportCommandTest that does
// not depend on import-specific globals.
func setupVaultForCommandTest(t *testing.T) (string, func()) {
	t.Helper()

	oldVaultDir := vaultDir
	oldProjectName := projectName
	oldJSONOutput := jsonOutput

	vaultPath := t.TempDir()
	v, err := ivault.Create(vaultPath, "test-passphrase")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v.Close()

	vaultDir = vaultPath
	projectName = ""
	jsonOutput = false
	t.Setenv("TVAULT_PASSPHRASE", "test-passphrase")

	return vaultPath, func() {
		vaultDir = oldVaultDir
		projectName = oldProjectName
		jsonOutput = oldJSONOutput
	}
}

func TestRunGetFromEnvFile(t *testing.T) {
	_, restore := setupVaultForCommandTest(t)
	defer restore()

	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("FROM_FILE=yes-from-file\nOTHER=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldFrom := getFromFile
	getFromFile = envFile
	defer func() { getFromFile = oldFrom }()

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := runGet(nil, []string{"FROM_FILE"}); err != nil {
		t.Fatalf("runGet: %v", err)
	}
	_ = w.Close()

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if out != "yes-from-file" {
		t.Errorf("got %q, want %q", out, "yes-from-file")
	}
}

func TestRunSetFromEnvFile(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("FROM_FILE=yes-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldFrom := setFromEnv
	oldKey := setKey
	setFromEnv = envFile
	setKey = ""
	defer func() {
		setFromEnv = oldFrom
		setKey = oldKey
	}()

	if err := runSet(nil, []string{"FROM_FILE"}); err != nil {
		t.Fatalf("runSet: %v", err)
	}

	v := openTestVault(t, vaultPath)
	got, err := v.GetSecret("default", "FROM_FILE")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "yes-from-file" {
		t.Errorf("got %q, want %q", got, "yes-from-file")
	}
}

func TestRunSetFromEnvFileWithRenamedKey(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("SOURCE_KEY=source-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldFrom := setFromEnv
	oldKey := setKey
	setFromEnv = envFile
	setKey = "SOURCE_KEY"
	defer func() {
		setFromEnv = oldFrom
		setKey = oldKey
	}()

	if err := runSet(nil, []string{"DEST_KEY"}); err != nil {
		t.Fatalf("runSet: %v", err)
	}

	v := openTestVault(t, vaultPath)
	got, err := v.GetSecret("default", "DEST_KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "source-value" {
		t.Errorf("got %q, want %q", got, "source-value")
	}
}

func TestRunSyncPullCreatesFile(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	// Seed two secrets in the vault.
	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "A", "1"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "B", "2"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	envFile := filepath.Join(t.TempDir(), ".env")
	oldPath := syncPath
	oldDir := syncDirection
	syncPath = envFile
	syncDirection = "pull"
	defer func() {
		syncPath = oldPath
		syncDirection = oldDir
	}()

	if err := runSync(nil, nil); err != nil {
		t.Fatalf("runSync: %v", err)
	}

	body, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"A=1", "B=2"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in %q", want, body)
		}
	}
}

func TestRunSyncPushWritesToVault(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("X=from-env\nY=also-from-env\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldPath := syncPath
	oldDir := syncDirection
	oldOverwrite := syncOverwrite
	syncPath = envFile
	syncDirection = "push"
	syncOverwrite = false
	defer func() {
		syncPath = oldPath
		syncDirection = oldDir
		syncOverwrite = oldOverwrite
	}()

	if err := runSync(nil, nil); err != nil {
		t.Fatalf("runSync: %v", err)
	}

	v := openTestVault(t, vaultPath)
	x, err := v.GetSecret("default", "X")
	if err != nil || x != "from-env" {
		t.Errorf("X = %q, err = %v", x, err)
	}
	y, err := v.GetSecret("default", "Y")
	if err != nil || y != "also-from-env" {
		t.Errorf("Y = %q, err = %v", y, err)
	}
}

func TestRunEncryptEnvDecryptEnvRoundTrip(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "foo-value"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// Encrypt a .env file.
	plaintextFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(plaintextFile, []byte("FOO=foo-value\nBAR=baz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	encryptedFile := filepath.Join(t.TempDir(), ".env.encrypted")

	oldIn := envEncryptIn
	oldOut := envEncryptOut
	envEncryptIn = plaintextFile
	envEncryptOut = encryptedFile
	defer func() {
		envEncryptIn = oldIn
		envEncryptOut = oldOut
	}()

	if err := runEnvEncrypt(nil, nil); err != nil {
		t.Fatalf("runEnvEncrypt: %v", err)
	}

	// Verify the encrypted file is not plaintext.
	encrypted, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), "FOO=foo-value") {
		t.Error("encrypted file appears to contain plaintext")
	}
	if !strings.HasPrefix(string(encrypted), "tvault-encrypted") {
		t.Errorf("missing magic header in encrypted file")
	}

	// Decrypt and check.
	envEncryptIn = encryptedFile
	envEncryptOut = filepath.Join(t.TempDir(), ".env.decrypted")
	if err := runEnvDecrypt(nil, nil); err != nil {
		t.Fatalf("runEnvDecrypt: %v", err)
	}
	decrypted, err := os.ReadFile(envEncryptOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decrypted), "FOO=foo-value") {
		t.Errorf("decrypted missing original content: %q", decrypted)
	}
}

func TestRunDocsFeaturesIsValidJSON(t *testing.T) {
	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Drain concurrently: the full catalog can exceed the pipe buffer.
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	if err := runDocs(nil, nil); err != nil {
		t.Fatalf("runDocs: %v", err)
	}
	_ = w.Close()
	out := <-done

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if _, ok := doc["features"]; !ok {
		t.Error("catalog missing features key")
	}
	if _, ok := doc["topics"]; !ok {
		t.Error("catalog missing topics key")
	}
}

func TestRunDocsTopicIsReadable(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := printTopic(fullCatalog(), "interpolate"); err != nil {
		t.Fatalf("printTopic: %v", err)
	}
	_ = w.Close()

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "tvault://") {
		t.Errorf("interpolate topic missing example: %s", out)
	}
}

func TestRunSearch(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "STRIPE_KEY", "sk_test"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "STRIPE_WEBHOOK", "whsec_test"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("default", "DATABASE_URL", "postgres://x"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Save and restore globals.
	oldProject := searchProject
	oldPrefix := searchPrefix
	searchProject = "default"
	searchPrefix = "STRIPE_"
	defer func() {
		searchProject = oldProject
		searchPrefix = oldPrefix
	}()

	if err := runSearch(nil, nil); err != nil {
		t.Fatalf("runSearch: %v", err)
	}
	_ = w.Close()

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "default/STRIPE_KEY") {
		t.Errorf("expected default/STRIPE_KEY in output, got %q", out)
	}
	if !strings.Contains(out, "default/STRIPE_WEBHOOK") {
		t.Errorf("expected default/STRIPE_WEBHOOK in output, got %q", out)
	}
	if strings.Contains(out, "default/DATABASE_URL") {
		t.Errorf("DATABASE_URL should be filtered out by prefix STRIPE_, got %q", out)
	}
}

func TestRunSearchJSON(t *testing.T) {
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()

	v := openTestVault(t, vaultPath)
	if err := v.SetSecret("default", "FOO", "foo-value"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	oldProject := searchProject
	searchProject = "default"
	defer func() { searchProject = oldProject }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := runSearch(nil, nil); err != nil {
		t.Fatalf("runSearch: %v", err)
	}
	_ = w.Close()

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	var doc map[string]any
	if err := json.Unmarshal(buf[:n], &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf[:n])
	}
	if doc["count"].(float64) != 1 {
		t.Errorf("expected count=1, got %v", doc["count"])
	}
}
