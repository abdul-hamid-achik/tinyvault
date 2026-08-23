package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/identity"
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

func sealThenOpenSetup(t *testing.T) (*VaultMCPServer, *crypto.Identity, string) {
	t.Helper()
	srv := sealTestServer(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rec := crypto.EncodeRecipient(id.Recipient())
	_, out, serr := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
		Recipients: []string{rec},
	})
	if serr != nil {
		t.Fatalf("seal: %v", serr)
	}
	t.Setenv("TVAULT_IDENTITY_KEY", crypto.EncodeIdentity(id))
	t.Setenv("TVAULT_IDENTITY", "")
	return srv, id, out.SealedBase64
}

func TestOpenSealedRoundTripToFile(t *testing.T) {
	srv, _, sealed := sealThenOpenSetup(t)
	outPath := filepath.Join(t.TempDir(), ".env")

	_, out, err := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		SealedBase64: sealed,
		OutputPath:   outPath,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if out.Path != outPath || out.Count != 2 {
		t.Errorf("got path=%q count=%d, want %s / 2", out.Path, out.Count, outPath)
	}
	if strings.Contains(fmt.Sprintf("%v", out), "sk_live_SECRET") {
		t.Fatal("plaintext leaked into the MCP result")
	}
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "API_KEY=sk_live_SECRET") || !strings.Contains(string(body), "DB_URL=postgres://x") {
		t.Errorf("written dotenv missing expected keys: %q", body)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("output perm = %#o, want 0600", perm)
	}
}

func TestOpenSealedFromPath(t *testing.T) {
	srv, id, _ := sealThenOpenSetup(t)
	sealedPath := filepath.Join(t.TempDir(), ".env.encrypted")
	rec := crypto.EncodeRecipient(id.Recipient())
	_, _, err := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
		Recipients: []string{rec},
		OutputPath: sealedPath,
	})
	if err != nil {
		t.Fatalf("seal to file: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), ".env")
	_, out, oerr := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		Path:       sealedPath,
		OutputPath: outPath,
	})
	if oerr != nil {
		t.Fatalf("open path: %v", oerr)
	}
	if out.Count != 2 {
		t.Errorf("count=%d, want 2", out.Count)
	}
}

func TestOpenSealedRequiresOutputPath(t *testing.T) {
	srv, _, sealed := sealThenOpenSetup(t)
	if _, _, err := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		SealedBase64: sealed,
	}); err == nil {
		t.Fatal("open without output_path should error")
	}
}

func TestOpenSealedRequiresExactlyOneInput(t *testing.T) {
	srv := sealTestServer(t)
	if _, _, err := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		OutputPath: filepath.Join(t.TempDir(), ".env"),
	}); err == nil {
		t.Fatal("open with neither path nor sealed_base64 should error")
	}
	if _, _, err := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		Path:         "a",
		SealedBase64: "b",
		OutputPath:   filepath.Join(t.TempDir(), ".env"),
	}); err == nil {
		t.Fatal("open with both path and sealed_base64 should error")
	}
}

func TestOpenSealedRejectsWrongIdentity(t *testing.T) {
	srv, _, sealed := sealThenOpenSetup(t)
	other, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TVAULT_IDENTITY_KEY", crypto.EncodeIdentity(other))
	_, _, oerr := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		SealedBase64: sealed,
		OutputPath:   filepath.Join(t.TempDir(), ".env"),
	})
	if oerr == nil {
		t.Fatal("wrong identity should fail to decrypt")
	}
}

func TestOpenSealedFiltersDeniedKeys(t *testing.T) {
	srv, _, sealed := sealThenOpenSetup(t)
	srv.policy.SecretsDeny = []string{"API_KEY"}
	outPath := filepath.Join(t.TempDir(), ".env")
	_, out, err := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		SealedBase64: sealed,
		OutputPath:   outPath,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if out.Count != 1 || (len(out.Keys) != 1 || out.Keys[0] != "DB_URL") {
		t.Errorf("expected only DB_URL after deny, got %+v", out)
	}
	body, _ := os.ReadFile(outPath)
	if strings.Contains(string(body), "API_KEY") {
		t.Errorf("denied key written to disk: %q", body)
	}
}

func TestOpenSealedRequiresWritePolicy(t *testing.T) {
	srv, _, sealed := sealThenOpenSetup(t)
	srv.policy.AccessMode = "read-only"
	if _, _, err := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		SealedBase64: sealed,
		OutputPath:   filepath.Join(t.TempDir(), ".env"),
	}); err == nil {
		t.Fatal("read-only policy should refuse to write a plaintext file")
	}
}

func TestOpenSealedNamedIdentityFile(t *testing.T) {
	srv := sealTestServer(t)
	rec, _, err := identity.New(srv.vault.Dir(), "ci")
	if err != nil {
		t.Fatal(err)
	}
	_, sealed, serr := srv.handleSealForRecipients(context.Background(), nil, sealForRecipientsInput{
		Recipients: []string{rec},
	})
	if serr != nil {
		t.Fatalf("seal: %v", serr)
	}
	t.Setenv("TVAULT_IDENTITY_KEY", "")
	outPath := filepath.Join(t.TempDir(), ".env")
	_, out, oerr := srv.handleOpenSealed(context.Background(), nil, openSealedInput{
		SealedBase64: sealed.SealedBase64,
		Identity:     "ci",
		OutputPath:   outPath,
	})
	if oerr != nil {
		t.Fatalf("open with named identity: %v", oerr)
	}
	if out.Count != 2 {
		t.Errorf("count=%d, want 2", out.Count)
	}
}
