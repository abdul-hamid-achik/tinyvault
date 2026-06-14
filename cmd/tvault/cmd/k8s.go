package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
)

// Kubernetes integration: the SealedSecret pattern keyed by the X25519
// recipient layer, with NO cluster controller. `tvault seal --format k8s`
// emits a commit-safe SealedSecret manifest (the v2 blob is ciphertext); at
// deploy, `tvault k8s render` decrypts it with the cluster's identity into a
// real Secret for `kubectl apply`. The rendered Secret is plaintext and must
// NOT be committed.

const sealedAPIVersion = "tinyvault.dev/v1"

type sealedSecret struct {
	APIVersion string           `yaml:"apiVersion"`
	Kind       string           `yaml:"kind"`
	Metadata   sealedSecretMeta `yaml:"metadata"`
	Spec       sealedSecretSpec `yaml:"spec"`
}

type sealedSecretMeta struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

type sealedSecretSpec struct {
	// Recipients the blob is sealed to (public, for transparency).
	Recipients []string `yaml:"recipients,omitempty"`
	// EncryptedData is a base64 tvault .env.encrypted v2 blob; commit-safe.
	EncryptedData string `yaml:"encryptedData"`
}

// k8sSealedManifest renders a commit-safe SealedSecret YAML wrapping the v2 blob.
func k8sSealedManifest(name, namespace string, recipients []string, blob []byte) ([]byte, error) {
	doc := sealedSecret{
		APIVersion: sealedAPIVersion,
		Kind:       "SealedSecret",
		Metadata:   sealedSecretMeta{Name: name, Namespace: namespace},
		Spec: sealedSecretSpec{
			Recipients:    recipients,
			EncryptedData: base64.StdEncoding.EncodeToString(blob),
		},
	}
	body, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("marshal SealedSecret: %w", err)
	}
	header := "# tvault SealedSecret — safe to commit (encryptedData is ciphertext).\n" +
		"# Render a real Secret at deploy with:\n" +
		"#   tvault k8s render --in <this-file> --identity <name> | kubectl apply -f -\n"
	return append([]byte(header), body...), nil
}

var (
	k8sIn       string
	k8sIdentity string
	k8sOut      string
)

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Kubernetes integration: commit-safe sealed Secrets",
	Long: `Commit-safe Kubernetes secrets, keyed by the X25519 recipient layer
(the SealedSecret pattern, without a cluster controller).

  # author (holds the cluster's public recipient):
  tvault seal --format k8s --name app-secrets --recipient tvault1cluster… -p prod > sealed.yaml
  git add sealed.yaml                       # commit-safe — encryptedData is ciphertext

  # deploy (holds the cluster identity, e.g. via TVAULT_IDENTITY_KEY):
  tvault k8s render --in sealed.yaml --identity cluster | kubectl apply -f -`,
}

var k8sRenderCmd = &cobra.Command{
	Use:   "render",
	Short: "Decrypt a SealedSecret into a real Kubernetes Secret",
	Long: `Read a SealedSecret manifest produced by 'tvault seal --format k8s',
decrypt it with a local identity (or TVAULT_IDENTITY_KEY), and emit a real
'kind: Secret' manifest for 'kubectl apply'.

The output contains PLAINTEXT secret values — pipe it to kubectl, do NOT
commit it. No vault unlock or passphrase is needed; only the identity.

Examples:
  tvault k8s render --in sealed.yaml --identity cluster | kubectl apply -f -
  TVAULT_IDENTITY_KEY=tvault-key1… tvault k8s render --in sealed.yaml | kubectl apply -f -`,
	RunE: runK8sRender,
}

func init() {
	rootCmd.AddCommand(k8sCmd)
	k8sCmd.AddCommand(k8sRenderCmd)
	k8sRenderCmd.Flags().StringVarP(&k8sIn, "in", "i", "", "SealedSecret input file (default: stdin)")
	k8sRenderCmd.Flags().StringVar(&k8sIdentity, "identity", "",
		"Identity to decrypt with (default: $TVAULT_IDENTITY_KEY, then a key file)")
	k8sRenderCmd.Flags().StringVarP(&k8sOut, "out", "o", "",
		"Write the rendered Secret here (default: stdout). It is PLAINTEXT — do not commit it")
}

func runK8sRender(_ *cobra.Command, _ []string) error {
	data, err := readInput(k8sIn)
	if err != nil {
		return err
	}
	var sealed sealedSecret
	if uerr := yaml.Unmarshal(data, &sealed); uerr != nil {
		return fmt.Errorf("parse SealedSecret: %w", uerr)
	}
	if sealed.Kind != "SealedSecret" || sealed.Spec.EncryptedData == "" {
		return fmt.Errorf("not a tvault SealedSecret manifest (kind=%q)", sealed.Kind)
	}
	blob, derr := base64.StdEncoding.DecodeString(sealed.Spec.EncryptedData)
	if derr != nil {
		return fmt.Errorf("decode encryptedData: %w", derr)
	}

	id, source, ierr := resolveIdentity(k8sIdentity)
	if ierr != nil {
		return ierr
	}
	if id == nil {
		return fmt.Errorf("no identity available: pass --identity <name> or set %s", envIdentityKey)
	}
	warnEnvKeyUsed(os.Stderr, source, "k8s render")

	plaintext, perr := encryptedenv.DecryptV2(id, blob)
	if perr != nil {
		if errors.Is(perr, crypto.ErrNoMatchingRecipient) {
			fmt.Fprintln(os.Stderr, "Tip: this identity is not a recipient of the sealed secret.")
		}
		return fmt.Errorf("decrypt: %w", perr)
	}
	parsed, perr := dotenv.ParseBytes(".env", plaintext)
	if perr != nil {
		return fmt.Errorf("parse sealed secrets: %w", perr)
	}

	stringData := make(map[string]string, len(parsed.Entries))
	keys := make([]string, 0, len(parsed.Entries))
	for _, e := range parsed.Entries {
		stringData[e.Key] = e.Value
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)

	secret := struct {
		APIVersion string            `yaml:"apiVersion"`
		Kind       string            `yaml:"kind"`
		Metadata   sealedSecretMeta  `yaml:"metadata"`
		Type       string            `yaml:"type"`
		StringData map[string]string `yaml:"stringData"`
	}{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata:   sealed.Metadata,
		Type:       "Opaque",
		StringData: stringData,
	}

	out, merr := yaml.Marshal(&secret)
	if merr != nil {
		return fmt.Errorf("marshal Secret: %w", merr)
	}

	fmt.Fprintln(os.Stderr, "WARNING: the rendered Secret contains PLAINTEXT values; pipe to kubectl, do not commit it.")
	if k8sOut == "" {
		_, werr := os.Stdout.Write(out)
		return werr
	}
	if werr := os.WriteFile(k8sOut, out, 0o600); werr != nil {
		return fmt.Errorf("write %s: %w", k8sOut, werr)
	}
	fmt.Fprintf(os.Stderr, "Rendered Secret %q (%d keys) → %s\n", sealed.Metadata.Name, len(keys), k8sOut)
	return nil
}
