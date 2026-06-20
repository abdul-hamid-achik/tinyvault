package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
	tvsync "github.com/abdul-hamid-achik/tinyvault/internal/sync"
)

// .env-oriented tools: drift diff, two-way sync, and commit-safe encrypted
// export. None return raw secret values (diff reports only same/differs
// verdicts; export returns ciphertext).

// --- vault_diff_env ---

type diffEnvInput struct {
	File          string `json:"file" jsonschema:"Path to a .env file to compare against the project."`
	Project       string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	CompareValues bool   `json:"compare_values,omitempty" jsonschema:"Also compare in-both keys by value, reporting only 'same'/'differs' (values are never returned)."`
}

type diffEnvOutput struct {
	Project     string            `json:"project"`
	File        string            `json:"file"`
	OnlyInVault []string          `json:"only_in_vault"`
	OnlyInFile  []string          `json:"only_in_file"`
	InBoth      []string          `json:"in_both"`
	ValueDiffs  map[string]string `json:"value_diffs,omitempty"`
	InSync      bool              `json:"in_sync"`
}

// --- vault_sync_env ---

type syncEnvInput struct {
	Direction string `json:"direction" jsonschema:"pull (vault→file), push (file→vault), or mirror (both, with conflict reporting)."`
	Path      string `json:"path,omitempty" jsonschema:"Dotenv file path. Default .env."`
	Project   string `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Overwrite bool   `json:"overwrite,omitempty" jsonschema:"Allow overwriting existing values on push/mirror."`
}

type syncConflictOut struct {
	Key        string `json:"key"`
	Resolution string `json:"resolution"`
}

type syncEnvOutput struct {
	Direction    string            `json:"direction"`
	Project      string            `json:"project"`
	Path         string            `json:"path"`
	EnvCreated   bool              `json:"env_created"`
	VaultEntries int               `json:"vault_entries"`
	EnvEntries   int               `json:"env_entries"`
	Created      []string          `json:"created"`
	Updated      []string          `json:"updated"`
	Skipped      []string          `json:"skipped"`
	Unchanged    []string          `json:"unchanged"`
	Conflicts    []syncConflictOut `json:"conflicts"`
}

// --- vault_export_env_encrypted ---

type exportEnvEncryptedInput struct {
	Project    string   `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	OutputPath string   `json:"output_path,omitempty" jsonschema:"Write the sealed .env.encrypted here and return only the path. If empty, the base64 ciphertext is returned."`
	Keys       []string `json:"keys,omitempty" jsonschema:"Specific keys to include. If omitted, all (policy-filtered)."`
}

type exportEnvEncryptedOutput struct {
	Path           string   `json:"path,omitempty"`
	SealedBase64   string   `json:"sealed_base64,omitempty"`
	Bytes          int      `json:"bytes"`
	Count          int      `json:"count"`
	Keys           []string `json:"keys"`
	RecipientCount int      `json:"recipient_count"`
}

func (s *VaultMCPServer) registerDotenvTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_diff_env",
		Description: "Compare a project against a .env file: which keys are only-in-vault, only-in-file, in " +
			"both, and (optionally) whether in-both values differ. Answers 'is my .env in sync?'. Reports " +
			"key names and same/differs verdicts only -- NEVER secret values.",
	}, s.handleDiffEnv)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_sync_env",
		Description: "Reconcile a .env file with a project: pull (vault→file), push (file→vault), or mirror " +
			"(both, conflicts reported). Returns key names and counts only -- NEVER secret values. push/mirror " +
			"are write ops.",
	}, s.handleSyncEnv)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_export_env_encrypted",
		Description: "Write a project's secrets as a commit-safe, passphrase-free .env.encrypted (v2) sealed to " +
			"the project's CURRENT recipients -- no need to list recipient strings. Output is ciphertext only " +
			"(a path or base64 blob); plaintext is NEVER returned. Errors if the project has no recipients " +
			"(share it first with vault_share_project, or use vault_seal_for_recipients with explicit recipients).",
	}, s.handleExportEnvEncrypted)
}

func (s *VaultMCPServer) handleDiffEnv(_ context.Context, _ *sdkmcp.CallToolRequest, input diffEnvInput) (*sdkmcp.CallToolResult, diffEnvOutput, error) {
	if input.File == "" {
		return nil, diffEnvOutput{}, fmt.Errorf("file is required")
	}
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, diffEnvOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}

	parsed, err := dotenv.ParseFile(input.File)
	if err != nil {
		return nil, diffEnvOutput{}, fmt.Errorf("parse %s: %w", input.File, err)
	}
	fileVals := make(map[string]string, len(parsed.Entries))
	for _, e := range parsed.Entries {
		fileVals[e.Key] = e.Value
	}

	keyList, err := s.vault.ListSecrets(project)
	if err != nil {
		return nil, diffEnvOutput{}, fmt.Errorf("list secrets: %w", err)
	}

	out := diffEnvOutput{Project: project, File: input.File}
	out.OnlyInVault, out.OnlyInFile, out.InBoth = s.bucketDiff(keyList, fileVals)
	out.InSync = len(out.OnlyInVault) == 0 && len(out.OnlyInFile) == 0

	if input.CompareValues {
		var allSame bool
		out.ValueDiffs, allSame = s.diffValues(project, out.InBoth, fileVals)
		out.InSync = out.InSync && allSame
		s.audit("secret.read", "secret", "", map[string]any{"project": project, "source": "diff", "compared": len(out.InBoth)})
	}

	return nil, out, nil
}

// bucketDiff partitions policy-filtered vault keys and file keys into
// only-in-vault, only-in-file, and in-both sets (all sorted).
func (s *VaultMCPServer) bucketDiff(vaultKeyList []string, fileVals map[string]string) (onlyVault, onlyFile, inBoth []string) {
	vaultKeys := make(map[string]struct{}, len(vaultKeyList))
	for _, k := range vaultKeyList {
		if s.policy.CanAccessSecret(k) {
			vaultKeys[k] = struct{}{}
		}
	}
	onlyVault, onlyFile, inBoth = []string{}, []string{}, []string{}
	for k := range vaultKeys {
		if _, ok := fileVals[k]; ok {
			inBoth = append(inBoth, k)
		} else {
			onlyVault = append(onlyVault, k)
		}
	}
	for k := range fileVals {
		if !s.policy.CanAccessSecret(k) {
			continue
		}
		if _, ok := vaultKeys[k]; !ok {
			onlyFile = append(onlyFile, k)
		}
	}
	sort.Strings(onlyVault)
	sort.Strings(onlyFile)
	sort.Strings(inBoth)
	return onlyVault, onlyFile, inBoth
}

// diffValues compares in-both keys by value, returning per-key verdicts
// ("same" | "differs" | "error") and whether all matched. Never returns values.
func (s *VaultMCPServer) diffValues(project string, inBoth []string, fileVals map[string]string) (map[string]string, bool) {
	diffs := make(map[string]string, len(inBoth))
	allSame := true
	for _, k := range inBoth {
		vv, err := s.vault.GetSecret(project, k)
		switch {
		case err != nil:
			diffs[k] = "error"
			allSame = false
		case vv == fileVals[k]:
			diffs[k] = "same"
		default:
			diffs[k] = "differs"
			allSame = false
		}
	}
	return diffs, allSame
}

func (s *VaultMCPServer) handleSyncEnv(_ context.Context, _ *sdkmcp.CallToolRequest, input syncEnvInput) (*sdkmcp.CallToolResult, syncEnvOutput, error) {
	dir, err := tvsync.ParseDirection(input.Direction)
	if err != nil {
		return nil, syncEnvOutput{}, err
	}
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, syncEnvOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	if dir != tvsync.Pull && !s.policy.CanWrite() {
		return nil, syncEnvOutput{}, fmt.Errorf("write access is disabled by policy (push/mirror require it)")
	}
	path := input.Path
	if path == "" {
		path = ".env"
	}

	res, err := tvsync.Sync(s.vault, project, path, dir, input.Overwrite)
	if err != nil {
		return nil, syncEnvOutput{}, fmt.Errorf("sync: %w", err)
	}

	out := syncEnvOutput{
		Direction:    dir.String(),
		Project:      project,
		Path:         res.Path,
		EnvCreated:   res.EnvCreated,
		VaultEntries: res.VaultEntries,
		EnvEntries:   res.EnvEntries,
		Created:      orEmpty(res.Created),
		Updated:      orEmpty(res.Updated),
		Skipped:      orEmpty(res.Skipped),
		Unchanged:    orEmpty(res.Unchanged),
		Conflicts:    []syncConflictOut{},
	}
	for _, c := range res.Conflicts {
		out.Conflicts = append(out.Conflicts, syncConflictOut{Key: c.Key, Resolution: c.Resolution})
	}
	if dir != tvsync.Pull {
		s.audit("env.sync", "env", project, map[string]any{
			"project":   project,
			"direction": dir.String(),
			"path":      path,
			"created":   len(res.Created),
			"updated":   len(res.Updated),
		})
	}
	return nil, out, nil
}

func (s *VaultMCPServer) handleExportEnvEncrypted(_ context.Context, _ *sdkmcp.CallToolRequest, input exportEnvEncryptedInput) (*sdkmcp.CallToolResult, exportEnvEncryptedOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, exportEnvEncryptedOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}
	pubs, err := s.vault.ProjectRecipients(project)
	if err != nil {
		return nil, exportEnvEncryptedOutput{}, fmt.Errorf("recipients: %w", err)
	}
	if len(pubs) == 0 {
		return nil, exportEnvEncryptedOutput{}, fmt.Errorf("project %q has no recipients; share it first (vault_share_project) or use vault_seal_for_recipients with explicit recipients", project)
	}

	all, err := s.vault.GetAllSecrets(project)
	if err != nil {
		return nil, exportEnvEncryptedOutput{}, fmt.Errorf("get secrets: %w", err)
	}
	selected, err := selectSealKeys(all, input.Keys, s.policy)
	if err != nil {
		return nil, exportEnvEncryptedOutput{}, err
	}

	body := dotenv.Marshal(selected)
	keys := make([]string, 0, len(selected))
	for k := range selected {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sealed, err := encryptedenv.EncryptV2(pubs, body)
	if err != nil {
		return nil, exportEnvEncryptedOutput{}, fmt.Errorf("seal: %w", err)
	}

	out := exportEnvEncryptedOutput{
		Bytes:          len(sealed),
		Count:          len(keys),
		Keys:           keys,
		RecipientCount: len(pubs),
	}
	if input.OutputPath != "" {
		if werr := os.WriteFile(input.OutputPath, sealed, 0o600); werr != nil {
			return nil, exportEnvEncryptedOutput{}, fmt.Errorf("write file: %w", werr)
		}
		out.Path = input.OutputPath
	} else {
		out.SealedBase64 = base64.StdEncoding.EncodeToString(sealed)
	}

	s.audit("secret.seal", "env", project, map[string]any{
		"project":    project,
		"recipients": len(pubs),
		"keys":       len(keys),
		"output":     out.Path,
		"source":     "export-encrypted",
	})
	return nil, out, nil
}

// orEmpty normalizes a nil slice to an empty one so JSON output is [] not null.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
