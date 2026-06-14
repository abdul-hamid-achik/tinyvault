package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
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

func (s *VaultMCPServer) registerSealTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_seal_for_recipients",
		Description: "Seal project secrets to one or more X25519 recipients (tvault1…), producing a " +
			"commit-safe .env.encrypted v2 blob that ONLY a holder of a matching private identity can open " +
			"(with `tvault decrypt-env --identity`). The returned bytes are ciphertext, so they are safe to " +
			"hand back to the conversation, commit, or send over any transport -- plaintext secret values are " +
			"NEVER returned. Use this to package secrets for a teammate, CI, or another agent without sharing " +
			"the passphrase.",
	}, s.handleSealForRecipients)
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

	allSecrets, err := s.vault.GetAllSecrets(project)
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
