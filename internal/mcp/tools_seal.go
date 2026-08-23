package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/identity"
)

type sealForRecipientsInput struct {
	Recipients []string `json:"recipients" jsonschema:"X25519 recipient strings (tvault1…) allowed to open the sealed blob. At least one required."`
	Project    string   `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Keys       []string `json:"keys,omitempty" jsonschema:"Specific secret keys to seal. If omitted seals all (policy-filtered)."`
	OutputPath string   `json:"output_path,omitempty" jsonschema:"If set, write the sealed bytes to this file (e.g. .env.encrypted) and return only the path. Otherwise the base64 sealed blob is returned."`
}

type sealForRecipientsOutput struct {
	Path           string   `json:"path,omitempty"`
	SealedBase64   string   `json:"sealed_base64,omitempty"`
	Bytes          int      `json:"bytes"`
	Count          int      `json:"count"`
	Keys           []string `json:"keys"`
	RecipientCount int      `json:"recipient_count"`
}

type openSealedInput struct {
	Path         string `json:"path,omitempty" jsonschema:"Path to a v2 .env.encrypted blob. Provide this or sealed_base64, not both."`
	SealedBase64 string `json:"sealed_base64,omitempty" jsonschema:"Base64 of a v2 blob (the sealed_base64 returned by vault_seal_for_recipients). Provide this or path, not both."`
	Identity     string `json:"identity,omitempty" jsonschema:"Identity name to decrypt with (default: $TVAULT_IDENTITY, else 'default'). Falls back to TVAULT_IDENTITY_KEY when no file exists."`
	OutputPath   string `json:"output_path" jsonschema:"Required. Write the decrypted dotenv here (0600). Plaintext is NEVER returned to the model."`
}

type openSealedOutput struct {
	Path  string   `json:"path"`
	Count int      `json:"count"`
	Keys  []string `json:"keys"`
}

func (s *VaultMCPServer) registerSealTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_seal_for_recipients",
		Description: "Seal project secrets to one or more X25519 recipients (tvault1…), producing a " +
			"commit-safe .env.encrypted v2 blob that ONLY a holder of a matching private identity can open " +
			"(with `tvault decrypt-env --identity` or vault_open_sealed). The returned bytes are ciphertext, so they are safe to " +
			"hand back to the conversation, commit, or send over any transport -- plaintext secret values are " +
			"NEVER returned. Use this to package secrets for a teammate, CI, or another agent without sharing " +
			"the passphrase.",
	}, s.handleSealForRecipients)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_open_sealed",
		Description: "Open a recipient-sealed v2 blob (from vault_seal_for_recipients, tvault seal, or " +
			"encrypt-env --recipient) with a local identity and write the decrypted dotenv to output_path " +
			"(0600). Returns only the path, key names, and count -- plaintext values are NEVER returned. " +
			"Identity is `identity`, else $TVAULT_IDENTITY, else 'default', else $TVAULT_IDENTITY_KEY. " +
			"v1 (passphrase) blobs are rejected; use decrypt-env for those. Write op.",
	}, s.handleOpenSealed)
}

func (s *VaultMCPServer) handleSealForRecipients(_ context.Context, _ *sdkmcp.CallToolRequest, input sealForRecipientsInput) (*sdkmcp.CallToolResult, sealForRecipientsOutput, error) {
	if len(input.Recipients) == 0 {
		return nil, sealForRecipientsOutput{}, fmt.Errorf("at least one recipient is required")
	}
	recipients := make([][]byte, 0, len(input.Recipients))
	for _, r := range input.Recipients {
		pub, err := crypto.DecodeRecipient(r)
		if err != nil {
			return nil, sealForRecipientsOutput{}, fmt.Errorf("recipient %q: %w", r, err)
		}
		recipients = append(recipients, pub)
	}

	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, sealForRecipientsOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}

	allSecrets, err := s.readAllSecrets(project)
	if err != nil {
		return nil, sealForRecipientsOutput{}, fmt.Errorf("get secrets: %w", err)
	}

	selected, err := selectSealKeys(allSecrets, input.Keys, s.policy)
	if err != nil {
		return nil, sealForRecipientsOutput{}, err
	}

	// Render a deterministic, round-trip-safe dotenv body, then seal it with
	// the same v2 format as `tvault encrypt-env --recipient` / the git clean
	// filter. dotenv.Marshal quotes multi-line and special-character values.
	body := dotenv.Marshal(selected)
	keys := make([]string, 0, len(selected))
	for k := range selected {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sealed, err := encryptedenv.EncryptV2(recipients, body)
	if err != nil {
		return nil, sealForRecipientsOutput{}, fmt.Errorf("seal: %w", err)
	}

	out := sealForRecipientsOutput{
		Bytes:          len(sealed),
		Count:          len(keys),
		Keys:           keys,
		RecipientCount: len(recipients),
	}
	if input.OutputPath != "" {
		if werr := os.WriteFile(input.OutputPath, sealed, 0o600); werr != nil {
			return nil, sealForRecipientsOutput{}, fmt.Errorf("write file: %w", werr)
		}
		out.Path = input.OutputPath
	} else {
		out.SealedBase64 = base64.StdEncoding.EncodeToString(sealed)
	}

	s.audit("secret.seal", "env", project, map[string]any{
		"project":    project,
		"recipients": len(recipients),
		"keys":       len(keys),
		"output":     out.Path,
	})
	return nil, out, nil
}

// selectSealKeys narrows the project's secrets to the requested keys (erroring
// on a missing one) and then drops any the policy disallows.
func selectSealKeys(all map[string]string, requested []string, policy *AccessPolicy) (map[string]string, error) {
	chosen := all
	if len(requested) > 0 {
		chosen = make(map[string]string, len(requested))
		for _, k := range requested {
			v, ok := all[k]
			if !ok {
				return nil, fmt.Errorf("secret %q not found", k)
			}
			chosen[k] = v
		}
	}
	filtered := make(map[string]string, len(chosen))
	for k, v := range chosen {
		if policy.CanAccessSecret(k) {
			filtered[k] = v
		}
	}
	return filtered, nil
}

func (s *VaultMCPServer) handleOpenSealed(_ context.Context, _ *sdkmcp.CallToolRequest, input openSealedInput) (*sdkmcp.CallToolResult, openSealedOutput, error) {
	if !s.policy.CanWrite() {
		return nil, openSealedOutput{}, fmt.Errorf("file exports are not allowed by policy")
	}
	if input.OutputPath == "" {
		return nil, openSealedOutput{}, fmt.Errorf("output_path is required (plaintext is written to disk, never returned)")
	}
	hasPath := input.Path != ""
	hasInline := input.SealedBase64 != ""
	if hasPath == hasInline {
		return nil, openSealedOutput{}, fmt.Errorf("provide exactly one of path or sealed_base64")
	}

	data, sourceKind, err := readSealedInput(input)
	if err != nil {
		return nil, openSealedOutput{}, err
	}

	ver, verr := encryptedenv.FileVersion(data)
	if verr != nil {
		return nil, openSealedOutput{}, fmt.Errorf("open: %w", verr)
	}
	if ver != 2 {
		return nil, openSealedOutput{}, fmt.Errorf("vault_open_sealed handles recipient-sealed (v2) blobs; this is v%d — use decrypt-env for passphrase files", ver)
	}

	id, idSource, ierr := s.resolveOpenIdentity(input.Identity)
	if ierr != nil {
		return nil, openSealedOutput{}, ierr
	}

	plaintext, derr := encryptedenv.DecryptV2(id, data)
	if derr != nil {
		return nil, openSealedOutput{}, fmt.Errorf("open: %w", derr)
	}
	defer crypto.ZeroBytes(plaintext)

	parsed, perr := dotenv.ParseBytes(input.OutputPath, plaintext)
	if perr != nil {
		return nil, openSealedOutput{}, fmt.Errorf("parse decrypted dotenv: %w", perr)
	}
	filtered := make(map[string]string, len(parsed.Entries))
	for _, e := range parsed.Entries {
		if s.policy.CanAccessSecret(e.Key) {
			filtered[e.Key] = e.Value
		}
	}
	body := dotenv.Marshal(filtered)
	if werr := os.WriteFile(input.OutputPath, body, 0o600); werr != nil {
		return nil, openSealedOutput{}, fmt.Errorf("write file: %w", werr)
	}

	keys := make([]string, 0, len(filtered))
	for k := range filtered {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	s.audit("secret.open", "env", input.OutputPath, map[string]any{
		"keys":     len(keys),
		"identity": idSource,
		"input":    sourceKind,
	})
	return nil, openSealedOutput{
		Path:  input.OutputPath,
		Count: len(keys),
		Keys:  keys,
	}, nil
}

func readSealedInput(input openSealedInput) (data []byte, kind string, err error) {
	if input.Path != "" {
		raw, rerr := os.ReadFile(input.Path)
		if rerr != nil {
			return nil, "", fmt.Errorf("read %s: %w", input.Path, rerr)
		}
		return raw, "path", nil
	}
	raw, berr := base64.StdEncoding.DecodeString(input.SealedBase64)
	if berr != nil {
		return nil, "", fmt.Errorf("decode sealed_base64: %w", berr)
	}
	return raw, "inline", nil
}

func (s *VaultMCPServer) resolveOpenIdentity(name string) (*crypto.Identity, string, error) {
	if name == "" {
		name = strings.TrimSpace(os.Getenv("TVAULT_IDENTITY"))
	}
	id, source, err := identity.Resolve(s.vaultDir(), name)
	if err != nil {
		return nil, "", err
	}
	if id == nil {
		return nil, "", fmt.Errorf("no identity available: pass identity, set TVAULT_IDENTITY, or set %s", identity.EnvKey)
	}
	return id, source, nil
}
