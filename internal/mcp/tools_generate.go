package mcp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type generateSecretInput struct {
	Project string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Key     string `json:"key" jsonschema:"The secret key name to store the generated value under."`
	Length  int    `json:"length,omitempty" jsonschema:"Length of the generated secret in characters (default 32)."`
	Charset string `json:"charset,omitempty" jsonschema:"Character set: alphanumeric, hex, base64, or ascii (default alphanumeric)."`
}

type generateSecretOutput struct {
	Key     string `json:"key"`
	Length  int    `json:"length"`
	Charset string `json:"charset"`
	Stored  bool   `json:"stored"`
}

const (
	charsetAlphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetASCII        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
)

func (s *VaultMCPServer) registerGenerateTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_generate_secret",
		Description: "Generate a cryptographically secure random secret and store it in the vault. " +
			"The generated value is NOT returned to the AI -- only confirmation that it was stored.",
	}, s.handleGenerateSecret)
}

func (s *VaultMCPServer) handleGenerateSecret(_ context.Context, _ *sdkmcp.CallToolRequest, input generateSecretInput) (*sdkmcp.CallToolResult, generateSecretOutput, error) {
	if !s.policy.CanWrite() {
		return nil, generateSecretOutput{}, fmt.Errorf("write operations are not allowed by policy (access_mode: %s)", s.policy.AccessMode)
	}

	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, generateSecretOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, generateSecretOutput{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	length := input.Length
	if length <= 0 {
		length = 32
	}
	if length > 256 {
		return nil, generateSecretOutput{}, fmt.Errorf("length must be at most 256")
	}

	charset := input.Charset
	if charset == "" {
		charset = "alphanumeric"
	}

	value, err := generateRandomString(length, charset)
	if err != nil {
		return nil, generateSecretOutput{}, fmt.Errorf("generate secret: %w", err)
	}

	if err := s.vault.SetSecret(project, input.Key, value); err != nil {
		return nil, generateSecretOutput{}, fmt.Errorf("store secret: %w", err)
	}

	s.audit("secret.generate", "secret", input.Key, map[string]any{"project": project, "charset": charset, "length": length})

	return nil, generateSecretOutput{
		Key:     input.Key,
		Length:  length,
		Charset: charset,
		Stored:  true,
	}, nil
}

func generateRandomString(length int, charset string) (string, error) {
	switch charset {
	case "hex":
		b := make([]byte, (length+1)/2)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b)[:length], nil
	case "base64":
		b := make([]byte, length)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		encoded := base64.URLEncoding.EncodeToString(b)
		if len(encoded) > length {
			encoded = encoded[:length]
		}
		return encoded, nil
	case "alphanumeric":
		return randomFromCharset(length, charsetAlphanumeric)
	case "ascii":
		return randomFromCharset(length, charsetASCII)
	default:
		return "", fmt.Errorf("unsupported charset %q (use alphanumeric, hex, base64, or ascii)", charset)
	}
}

func randomFromCharset(length int, charset string) (string, error) {
	charsetLen := big.NewInt(int64(len(charset)))
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}
