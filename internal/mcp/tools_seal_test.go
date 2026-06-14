package mcp

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func sealTestServer(t *testing.T) *VaultMCPServer {
	t.Helper()
	v, err := vault.Create(t.TempDir(), "pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	for k, val := range map[string]string{"DB_URL": "postgres://x", "API_KEY": "sk_live_SECRET"} {
		if err := v.SetSecret("default", k, val); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	return NewVaultMCPServer(v, DefaultPolicy())
}

func TestSealForRecipientsRoundTrip(t *testing.T) {
	srv := sealTestServer(t)
	id, _ := crypto.GenerateIdentity()
	rec := crypto.EncodeRecipient(id.Recipient())

	_, out, err := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
		Recipients: []string{rec},
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if out.SealedBase64 == "" {
		t.Fatal("expected an inline sealed blob")
	}
	if out.Count != 2 || out.RecipientCount != 1 {
		t.Errorf("count=%d recipients=%d, want 2/1", out.Count, out.RecipientCount)
	}

	// The model-facing output must never contain a plaintext secret value.
	if strings.Contains(out.SealedBase64, "sk_live_SECRET") {
		t.Fatal("plaintext leaked into the base64 output")
	}
	sealed, err := base64.StdEncoding.DecodeString(out.SealedBase64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if strings.Contains(string(sealed), "sk_live_SECRET") {
		t.Fatal("plaintext leaked into the sealed bytes")
	}

	// It is a v2 file the recipient can open back to the original dotenv.
	if v, _ := encryptedenv.FileVersion(sealed); v != 2 {
		t.Fatalf("sealed blob is not v2: %d", v)
	}
	pt, err := encryptedenv.DecryptV2(id, sealed)
	if err != nil {
		t.Fatalf("recipient decrypt: %v", err)
	}
	body := string(pt)
	if !strings.Contains(body, "API_KEY=sk_live_SECRET") || !strings.Contains(body, "DB_URL=postgres://x") {
		t.Errorf("sealed dotenv missing expected keys: %q", body)
	}
}

func TestSealForRecipientsRequiresRecipient(t *testing.T) {
	srv := sealTestServer(t)
	if _, _, err := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{}); err == nil {
		t.Fatal("seal with no recipients should error")
	}
}

func TestSealForRecipientsRejectsBadRecipient(t *testing.T) {
	srv := sealTestServer(t)
	_, _, err := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
		Recipients: []string{"not-a-recipient"},
	})
	if err == nil {
		t.Fatal("an invalid recipient string should error")
	}
}

func TestSealForRecipientsKeySubsetToFile(t *testing.T) {
	srv := sealTestServer(t)
	id, _ := crypto.GenerateIdentity()
	rec := crypto.EncodeRecipient(id.Recipient())
	path := filepath.Join(t.TempDir(), ".env.encrypted")

	_, out, err := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
		Recipients: []string{rec},
		Keys:       []string{"API_KEY"},
		OutputPath: path,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if out.Path != path || out.SealedBase64 != "" {
		t.Errorf("expected file output with no inline blob, got %+v", out)
	}
	if out.Count != 1 {
		t.Errorf("expected 1 sealed key, got %d", out.Count)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sealed file: %v", err)
	}
	pt, err := encryptedenv.DecryptV2(id, data)
	if err != nil {
		t.Fatalf("decrypt sealed file: %v", err)
	}
	if strings.Contains(string(pt), "DB_URL") {
		t.Errorf("key subset not honored — DB_URL should be excluded: %q", pt)
	}
}

func TestSealForRecipientsMissingKey(t *testing.T) {
	srv := sealTestServer(t)
	id, _ := crypto.GenerateIdentity()
	rec := crypto.EncodeRecipient(id.Recipient())
	_, _, err := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
		Recipients: []string{rec},
		Keys:       []string{"DOES_NOT_EXIST"},
	})
	if err == nil {
		t.Fatal("sealing a non-existent key should error")
	}
}
