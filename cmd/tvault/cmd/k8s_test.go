package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

func resetK8sFlags(t *testing.T) {
	t.Helper()
	f, n, ns, o := sealFormat, sealK8sName, sealK8sNamespace, sealOut
	in, id, ko := k8sIn, k8sIdentity, k8sOut
	t.Cleanup(func() {
		sealFormat, sealK8sName, sealK8sNamespace, sealOut = f, n, ns, o
		k8sIn, k8sIdentity, k8sOut = in, id, ko
	})
}

// sealK8sManifest seals the vault's secrets to id and returns the manifest bytes.
func sealK8sManifest(t *testing.T, name string, id *crypto.Identity) []byte {
	t.Helper()
	resetSealFlags(t)
	sealRecipients = []string{crypto.EncodeRecipient(id.Recipient())}
	sealFormat, sealK8sName, sealK8sNamespace, sealOut = "k8s", name, "prod", ""
	out := captureStdout(t, func() {
		if err := runSeal(nil, nil); err != nil {
			t.Fatalf("seal --format k8s: %v", err)
		}
	})
	return out
}

func TestK8sSealRenderRoundTrip(t *testing.T) {
	resetK8sFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "DB_URL", "postgres://x")
	setVersionsForCLI(t, vaultPath, "CERT", "a\nb") // multi-line

	id := mustGenIdentity(t)
	writeTestIdentity(t, "cluster", id)

	manifest := sealK8sManifest(t, "app-secrets", id)
	if !strings.Contains(string(manifest), "kind: SealedSecret") {
		t.Fatalf("not a SealedSecret manifest:\n%s", manifest)
	}
	if strings.Contains(string(manifest), "postgres://x") {
		t.Fatal("plaintext leaked into the sealed manifest")
	}

	// Render with the identity.
	path := filepath.Join(t.TempDir(), "sealed.yaml")
	if err := os.WriteFile(path, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	k8sIn, k8sIdentity, k8sOut = path, "cluster", ""
	rendered := captureStdout(t, func() {
		if err := runK8sRender(nil, nil); err != nil {
			t.Fatalf("k8s render: %v", err)
		}
	})

	var secret struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
		StringData map[string]string `yaml:"stringData"`
	}
	if err := yaml.Unmarshal(rendered, &secret); err != nil {
		t.Fatalf("rendered Secret not valid YAML: %v\n%s", err, rendered)
	}
	if secret.Kind != "Secret" || secret.Metadata.Name != "app-secrets" || secret.Metadata.Namespace != "prod" {
		t.Errorf("unexpected Secret metadata: %+v", secret)
	}
	if secret.StringData["DB_URL"] != "postgres://x" {
		t.Errorf("DB_URL = %q", secret.StringData["DB_URL"])
	}
	if secret.StringData["CERT"] != "a\nb" {
		t.Errorf("multi-line CERT corrupted: %q", secret.StringData["CERT"])
	}
}

func TestK8sRenderViaEnvKey(t *testing.T) {
	resetK8sFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "K", "v")

	id := mustGenIdentity(t)
	writeTestIdentity(t, "cluster", id)
	manifest := sealK8sManifest(t, "app", id)

	// Render with TVAULT_IDENTITY_KEY only (no --identity), like a CI deploy.
	withVaultDir(t, t.TempDir()) // empty: no identity files
	t.Setenv(envIdentityKey, crypto.EncodeIdentity(id))
	path := filepath.Join(t.TempDir(), "sealed.yaml")
	if err := os.WriteFile(path, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	k8sIn, k8sIdentity, k8sOut = path, "", ""
	out := captureStdout(t, func() {
		if err := runK8sRender(nil, nil); err != nil {
			t.Fatalf("k8s render via env key: %v", err)
		}
	})
	if !strings.Contains(string(out), "K: v") {
		t.Errorf("env-key render missing secret:\n%s", out)
	}
}

func TestK8sRenderRejectsNonSealedSecret(t *testing.T) {
	resetK8sFlags(t)
	withVaultDir(t, t.TempDir())
	path := filepath.Join(t.TempDir(), "cm.yaml")
	if err := os.WriteFile(path, []byte("kind: ConfigMap\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k8sIn, k8sIdentity = path, "x"
	if err := runK8sRender(nil, nil); err == nil {
		t.Fatal("rendering a non-SealedSecret should error")
	}
}

func TestK8sRenderNoIdentity(t *testing.T) {
	resetK8sFlags(t)
	withVaultDir(t, t.TempDir())
	t.Setenv(envIdentityKey, "")
	id := mustGenIdentity(t)
	blob, _ := encryptedenv.EncryptV2([][]byte{id.Recipient()}, []byte("A=1\n"))
	manifest, _ := k8sSealedManifest("app", "default", nil, blob)
	path := filepath.Join(t.TempDir(), "sealed.yaml")
	if err := os.WriteFile(path, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	k8sIn, k8sIdentity = path, "" // no file, no env key → locked
	if err := runK8sRender(nil, nil); err == nil {
		t.Fatal("render with no available identity should error")
	}
}

func TestSealFormatK8sRequiresName(t *testing.T) {
	resetK8sFlags(t)
	id := mustGenIdentity(t)
	old := sealRecipients
	sealRecipients = []string{crypto.EncodeRecipient(id.Recipient())}
	defer func() { sealRecipients = old }()
	sealFormat, sealK8sName = "k8s", ""
	if err := runSeal(nil, nil); err == nil {
		t.Fatal("--format k8s without --name should error")
	}
}

func TestSealFormatInvalid(t *testing.T) {
	resetK8sFlags(t)
	sealFormat = "bogus"
	if err := runSeal(nil, nil); err == nil {
		t.Fatal("an invalid --format should error")
	}
}

func TestK8sRenderWrongIdentity(t *testing.T) {
	resetK8sFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "K", "v")

	alice := mustGenIdentity(t)
	bob := mustGenIdentity(t)
	writeTestIdentity(t, "bob", bob)
	manifest := sealK8sManifest(t, "app", alice) // sealed to alice only

	path := filepath.Join(t.TempDir(), "sealed.yaml")
	if err := os.WriteFile(path, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	k8sIn, k8sIdentity = path, "bob" // not a recipient
	if err := runK8sRender(nil, nil); err == nil {
		t.Fatal("render with a non-recipient identity must fail")
	}
}

func TestK8sManifestHasRecipients(t *testing.T) {
	resetK8sFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "K", "v")
	id := mustGenIdentity(t)
	manifest := sealK8sManifest(t, "app", id)

	var doc struct {
		Spec struct {
			Recipients []string `yaml:"recipients"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifest, &doc); err != nil {
		t.Fatalf("manifest not valid YAML: %v", err)
	}
	want := crypto.EncodeRecipient(id.Recipient())
	if len(doc.Spec.Recipients) != 1 || doc.Spec.Recipients[0] != want {
		t.Errorf("spec.recipients = %v, want [%s] (transparency field)", doc.Spec.Recipients, want)
	}
}

func TestSealK8sWithKeySubset(t *testing.T) {
	resetK8sFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "DB_URL", "x")
	setVersionsForCLI(t, vaultPath, "SECRET_TOKEN", "y")

	id := mustGenIdentity(t)
	writeTestIdentity(t, "cluster", id)

	resetSealFlags(t)
	sealRecipients = []string{crypto.EncodeRecipient(id.Recipient())}
	sealKeys = []string{"DB_URL"} // only one
	sealFormat, sealK8sName, sealOut = "k8s", "app", ""
	manifest := captureStdout(t, func() {
		if err := runSeal(nil, nil); err != nil {
			t.Fatalf("seal --format k8s --key: %v", err)
		}
	})

	path := filepath.Join(t.TempDir(), "sealed.yaml")
	if err := os.WriteFile(path, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	k8sIn, k8sIdentity, k8sOut = path, "cluster", ""
	rendered := captureStdout(t, func() {
		if err := runK8sRender(nil, nil); err != nil {
			t.Fatalf("k8s render: %v", err)
		}
	})
	if !strings.Contains(string(rendered), "DB_URL") {
		t.Error("rendered Secret should contain the selected key")
	}
	if strings.Contains(string(rendered), "SECRET_TOKEN") {
		t.Error("--key subset not honored for --format k8s (excluded key leaked)")
	}
}

func TestSealK8sMultipleRecipients(t *testing.T) {
	resetK8sFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "K", "shared")

	alice := mustGenIdentity(t)
	bob := mustGenIdentity(t)
	writeTestIdentity(t, "alice", alice)
	writeTestIdentity(t, "bob", bob)

	resetSealFlags(t)
	sealRecipients = []string{crypto.EncodeRecipient(alice.Recipient()), crypto.EncodeRecipient(bob.Recipient())}
	sealFormat, sealK8sName, sealOut = "k8s", "app", ""
	manifest := captureStdout(t, func() {
		if err := runSeal(nil, nil); err != nil {
			t.Fatalf("seal --format k8s multi-recipient: %v", err)
		}
	})
	path := filepath.Join(t.TempDir(), "sealed.yaml")
	if err := os.WriteFile(path, manifest, 0o600); err != nil {
		t.Fatal(err)
	}

	// Both recipients can render independently.
	for _, name := range []string{"alice", "bob"} {
		k8sIn, k8sIdentity, k8sOut = path, name, ""
		out := captureStdout(t, func() {
			if err := runK8sRender(nil, nil); err != nil {
				t.Fatalf("render as %s: %v", name, err)
			}
		})
		if !strings.Contains(string(out), "K: shared") {
			t.Errorf("render as %s missing the secret:\n%s", name, out)
		}
	}
}
