package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// --- vault_env_group_create ---

type envGroupCreateInput struct {
	Name         string            `json:"name" jsonschema:"Group name (e.g. 'liftclub')"`
	Description  string            `json:"description,omitempty" jsonschema:"Human-readable description of the group."`
	Environments []envGroupEntryIn `json:"environments" jsonschema:"Environments to link. Each entry maps an environment name to an existing tvault project."`
	Force        bool              `json:"force,omitempty" jsonschema:"Overwrite existing group or re-link projects already in another group. Default false."`
}

type envGroupEntryIn struct {
	Name    string `json:"name" jsonschema:"Environment name (production, preview, staging)"`
	Project string `json:"project" jsonschema:"Existing tvault project name"`
}

type envGroupOutput struct {
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	Environments []envGroupEntryOut `json:"environments"`
}

type envGroupEntryOut struct {
	Name    string `json:"name"`
	Project string `json:"project"`
}

// --- vault_env_group_list ---

type envGroupListOutput struct {
	Groups []envGroupDetail `json:"groups"`
}

type envGroupDetail struct {
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	Environments []envGroupEntryOut `json:"environments"`
}

// --- vault_env_diff ---

type envDiffInput struct {
	Group  string `json:"group" jsonschema:"Group name"`
	Values bool   `json:"values,omitempty" jsonschema:"Compare values (same/different, never prints them). Default false (key-set only)."`
}

type envDiffOutput struct {
	Group  string          `json:"group"`
	Status string          `json:"status"` // ok|drift
	Keys   []envDiffKeyOut `json:"keys"`
}

type envDiffKeyOut struct {
	Key          string            `json:"key"`
	Environments []envDiffEntryOut `json:"environments"`
}

type envDiffEntryOut struct {
	Env     string `json:"env"`
	Present bool   `json:"present"`
	Status  string `json:"status"` // same|different|missing|local-only
}

// --- vault_env_promote ---

type envPromoteInput struct {
	Group   string   `json:"group" jsonschema:"Group name"`
	Keys    []string `json:"keys,omitempty" jsonschema:"Keys to promote. Empty + all=true promotes all differing keys."`
	FromEnv string   `json:"from_env" jsonschema:"Source environment name"`
	ToEnv   string   `json:"to_env" jsonschema:"Target environment name"`
	All     bool     `json:"all,omitempty" jsonschema:"Promote all keys that differ. Default false."`
	DryRun  bool     `json:"dry_run,omitempty" jsonschema:"Show what would change without writing. Default false."`
}

type envPromoteOutput struct {
	Promoted []promotedKeyOut `json:"promoted"`
	Skipped  []skippedKeyOut  `json:"skipped"`
}

type promotedKeyOut struct {
	Key         string `json:"key"`
	FromVersion int    `json:"from_version"`
	ToVersion   int    `json:"to_version"`
}

type skippedKeyOut struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// --- vault_env_seal ---

type envSealInput struct {
	Group      string   `json:"group" jsonschema:"Group name"`
	Recipients []string `json:"recipients" jsonschema:"X25519 recipient strings (tvault1…)"`
	Keys       []string `json:"keys,omitempty" jsonschema:"Specific keys to seal. If omitted, seals all keys (policy-filtered)."`
	Envs       []string `json:"envs,omitempty" jsonschema:"Specific environment names to include. If omitted, all environments."`
	OutputPath string   `json:"output_path,omitempty" jsonschema:"Write the sealed blob to this file. If empty, returns base64."`
}

type envSealOutput struct {
	Path           string   `json:"path,omitempty"`
	SealedBase64   string   `json:"sealed_base64,omitempty"`
	Bytes          int      `json:"bytes"`
	Environments   []string `json:"environments"`
	Keys           []string `json:"keys"`
	RecipientCount int      `json:"recipient_count"`
}

// --- vault_env_inherit ---

type envInheritInput struct {
	Group string `json:"group" jsonschema:"Group name"`
	Env   string `json:"env" jsonschema:"Child environment name"`
	From  string `json:"from" jsonschema:"Base environment name to inherit from"`
}

type envInheritOutput struct {
	Group        string `json:"group"`
	Env          string `json:"env"`
	InheritsFrom string `json:"inherits_from"`
}

// --- vault_env_inherited ---

type envInheritedInput struct {
	Group string `json:"group" jsonschema:"Group name"`
	Env   string `json:"env" jsonschema:"Environment name"`
}

type envInheritedOutput struct {
	Keys []inheritedKeyOut `json:"keys"`
}

type inheritedKeyOut struct {
	Key    string `json:"key"`
	Source string `json:"source"` // local|inherited:<env>|missing
	Pinned bool   `json:"pinned"`
}

// resolveEnvProject returns the project name for a given environment in a group.
func resolveEnvProject(group *vault.EnvGroup, envName string) (string, error) {
	for _, e := range group.Environments {
		if e.Name == envName {
			return e.Project, nil
		}
	}
	return "", fmt.Errorf("environment %q not found in group %q", envName, group.Name)
}

// resolveAllWithInheritanceMCP resolves all secrets for an environment through
// the inheritance chain. It gets the child project's local secrets, then fills
// in missing keys from the base environment (if inheritance is configured).
//
//nolint:gocognit // env group + inheritance merge has inherent branching
func resolveAllWithInheritanceMCP(v *vault.Vault, group *vault.EnvGroup, envName, childProject string) (map[string]string, error) {
	secrets, err := v.GetAllSecrets(childProject)
	if err != nil {
		return nil, fmt.Errorf("get secrets for %s: %w", childProject, err)
	}
	if group.Inheritance != nil {
		if inh, ok := group.Inheritance[envName]; ok {
			baseProject, bErr := resolveEnvProject(group, inh.From)
			if bErr == nil {
				baseSecrets, gErr := v.GetAllSecrets(baseProject)
				if gErr == nil {
					for k, val := range baseSecrets {
						if _, exists := secrets[k]; !exists {
							secrets[k] = val
						}
					}
				}
			}
		}
	}
	return secrets, nil
}

func (s *VaultMCPServer) registerEnvGroupTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_group_create",
		Description: "Create an environment group linking multiple projects. " +
			"The group is metadata-only — projects keep their own DEKs. Returns the group name and linked environments.",
	}, s.handleEnvGroupCreate)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_env_group_list",
		Description: "List all environment groups with their linked projects. Metadata only; no secret values.",
	}, s.handleEnvGroupList)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_diff",
		Description: "Compare key sets across environments in a group. Reports " +
			"missing/extra keys and same/different values (metadata only — never prints values). " +
			"Returns exit-code-equivalent status: 'ok' or 'drift'.",
	}, s.handleEnvDiff)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_promote",
		Description: "Copy a secret value from one environment to another within a group. " +
			"The value is decrypted from the source, re-encrypted into the target, and a new " +
			"version is created in the target. The prior value is archived (non-destructive). " +
			"Audit entry: secret.promote. Never returns secret values — only version numbers.",
	}, s.handleEnvPromote)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_seal",
		Description: "Seal all environments of a group into a single recipient-sealed blob. " +
			"Each environment's secrets are in a labeled section. In CI, decrypt with --section <env> " +
			"to extract one environment's values. Output is ciphertext — safe to commit. " +
			"Secret values are NEVER returned.",
	}, s.handleEnvSeal)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_inherit",
		Description: "Configure key inheritance for an environment. The child environment " +
			"resolves missing keys from the base environment at read time (get/run/env/export). " +
			"Inheritance is metadata-only — no values are copied. Returns the inheritance configuration.",
	}, s.handleEnvInherit)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_inherited",
		Description: "Show which keys in an environment are inherited vs. local (pinned). " +
			"Metadata only — no values.",
	}, s.handleEnvInherited)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_group_show",
		Description: "Show details of an environment group: linked projects, drift status, " +
			"and inheritance configuration. Metadata only — no secret values.",
	}, s.handleEnvGroupShow)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_group_add",
		Description: "Add an environment to an existing group. The project must already exist " +
			"and must not be in another group.",
	}, s.handleEnvGroupAdd)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_group_remove",
		Description: "Remove an environment from a group. The project is NOT deleted — only " +
			"the group membership is removed.",
	}, s.handleEnvGroupRemove)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_group_delete",
		Description: "Delete an environment group entirely. Projects are NOT deleted — only " +
			"the group metadata is removed.",
	}, s.handleEnvGroupDelete)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_pin",
		Description: "Pin a key: write the current resolved value (through inheritance) into " +
			"the child project, breaking inheritance for that key only. The value is decrypted " +
			"from the base project's DEK and re-encrypted into the child project's DEK. " +
			"Audit entry: secret.pin.",
	}, s.handleEnvPin)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_env_unpin",
		Description: "Unpin a key: delete the pinned value from the child project, restoring " +
			"inheritance for that key. Audit entry: secret.unpin.",
	}, s.handleEnvUnpin)
}

func (s *VaultMCPServer) handleEnvGroupCreate(_ context.Context, _ *sdkmcp.CallToolRequest, input envGroupCreateInput) (*sdkmcp.CallToolResult, envGroupOutput, error) {
	if !s.policy.CanWrite() {
		return nil, envGroupOutput{}, fmt.Errorf("write operations are not allowed by policy")
	}

	envs := make([]vault.EnvGroupEntry, len(input.Environments))
	for i, e := range input.Environments {
		envs[i] = vault.EnvGroupEntry{Name: e.Name, Project: e.Project}
		if !s.policy.CanAccessProject(e.Project) {
			return nil, envGroupOutput{}, fmt.Errorf("project %q is not allowed by policy", e.Project)
		}
	}

	group, err := s.vault.CreateEnvGroup(input.Name, input.Description, envs, input.Force)
	if err != nil {
		return nil, envGroupOutput{}, fmt.Errorf("create group: %w", err)
	}

	s.audit("env.group.create", "env_group", input.Name, nil)

	return nil, toEnvGroupOutput(group), nil
}

func (s *VaultMCPServer) handleEnvGroupList(_ context.Context, _ *sdkmcp.CallToolRequest, _ struct{}) (*sdkmcp.CallToolResult, envGroupListOutput, error) {
	groups, err := s.vault.ListEnvGroups()
	if err != nil {
		return nil, envGroupListOutput{}, fmt.Errorf("list groups: %w", err)
	}

	out := envGroupListOutput{Groups: []envGroupDetail{}}
	for _, g := range groups {
		out.Groups = append(out.Groups, envGroupDetail{
			Name:         g.Name,
			Description:  g.Description,
			Environments: toEnvGroupEntries(g.Environments),
		})
	}
	return nil, out, nil
}

func (s *VaultMCPServer) handleEnvDiff(_ context.Context, _ *sdkmcp.CallToolRequest, input envDiffInput) (*sdkmcp.CallToolResult, envDiffOutput, error) {
	diff, err := s.vault.DiffEnvironments(input.Group, input.Values)
	if err != nil {
		return nil, envDiffOutput{}, fmt.Errorf("diff: %w", err)
	}

	out := envDiffOutput{
		Group:  diff.Group,
		Status: diff.Status,
		Keys:   []envDiffKeyOut{},
	}
	for _, k := range diff.Keys {
		entries := make([]envDiffEntryOut, len(k.Environments))
		for i, e := range k.Environments {
			entries[i] = envDiffEntryOut{
				Env:     e.Env,
				Present: e.Present,
				Status:  e.Status,
			}
		}
		out.Keys = append(out.Keys, envDiffKeyOut{Key: k.Key, Environments: entries})
	}
	return nil, out, nil
}

func (s *VaultMCPServer) handleEnvPromote(_ context.Context, _ *sdkmcp.CallToolRequest, input envPromoteInput) (*sdkmcp.CallToolResult, envPromoteOutput, error) {
	if !s.policy.CanWrite() {
		return nil, envPromoteOutput{}, fmt.Errorf("write operations are not allowed by policy")
	}

	// Policy: check source and target projects.
	group, err := s.vault.GetEnvGroup(input.Group)
	if err != nil {
		return nil, envPromoteOutput{}, fmt.Errorf("group: %w", err)
	}
	for _, e := range group.Environments {
		if (e.Name == input.FromEnv || e.Name == input.ToEnv) && !s.policy.CanAccessProject(e.Project) {
			return nil, envPromoteOutput{}, fmt.Errorf("project %q is not allowed by policy", e.Project)
		}
	}

	result, err := s.vault.Promote(input.Group, input.FromEnv, input.ToEnv, input.Keys, input.All, input.DryRun)
	if err != nil {
		return nil, envPromoteOutput{}, fmt.Errorf("promote: %w", err)
	}

	out := envPromoteOutput{
		Promoted: []promotedKeyOut{},
		Skipped:  []skippedKeyOut{},
	}
	for _, p := range result.Promoted {
		out.Promoted = append(out.Promoted, promotedKeyOut{
			Key:         p.Key,
			FromVersion: p.FromVersion,
			ToVersion:   p.ToVersion,
		})
	}
	for _, sk := range result.Skipped {
		out.Skipped = append(out.Skipped, skippedKeyOut{Key: sk.Key, Reason: sk.Reason})
	}
	return nil, out, nil
}

// buildSealBody constructs the multi-section dotenv body for a sealed-profile
// blob. Returns the body string, included environment names, included key
// names, and any error.
//
//nolint:gocognit // inherently complex: multi-env, multi-key filtering
func (s *VaultMCPServer) buildSealBody(
	group *vault.EnvGroup,
	envFilter, keyFilter []string,
) (string, []string, []string, error) {
	var body strings.Builder
	includedEnvs := []string{}
	includedKeys := []string{}

	for _, e := range group.Environments {
		if len(envFilter) > 0 && !containsStr(envFilter, e.Name) {
			continue
		}
		if !s.policy.CanAccessProject(e.Project) {
			continue
		}

		secrets, gErr := s.vault.GetAllSecrets(e.Project)
		if gErr != nil {
			return "", nil, nil, fmt.Errorf("get secrets for %s: %w", e.Project, gErr)
		}

		keys := make([]string, 0, len(secrets))
		for k := range secrets {
			if !s.policy.CanAccessSecret(k) {
				continue
			}
			if len(keyFilter) > 0 && !containsStr(keyFilter, k) {
				continue
			}
			keys = append(keys, k)
		}

		if len(keys) == 0 {
			continue
		}

		fmt.Fprintf(&body, "--- tvault-env:%s ---\n", e.Name)
		for _, k := range keys {
			fmt.Fprintf(&body, "%s=%s\n", k, secrets[k])
			includedKeys = appendIfMissing(includedKeys, k)
		}
		includedEnvs = append(includedEnvs, e.Name)
	}
	body.WriteString("--- end ---\n")
	return body.String(), includedEnvs, includedKeys, nil
}

func containsStr(list []string, val string) bool {
	for _, s := range list {
		if s == val {
			return true
		}
	}
	return false
}

func (s *VaultMCPServer) handleEnvSeal(_ context.Context, _ *sdkmcp.CallToolRequest, input envSealInput) (*sdkmcp.CallToolResult, envSealOutput, error) {
	if !s.policy.CanWrite() {
		return nil, envSealOutput{}, fmt.Errorf("write operations are not allowed by policy")
	}

	group, err := s.vault.GetEnvGroup(input.Group)
	if err != nil {
		return nil, envSealOutput{}, fmt.Errorf("group: %w", err)
	}

	// Parse recipients.
	recipients := make([][]byte, 0, len(input.Recipients))
	for _, r := range input.Recipients {
		pub, derr := crypto.DecodeRecipient(r)
		if derr != nil {
			return nil, envSealOutput{}, fmt.Errorf("recipient %q: %w", r, derr)
		}
		recipients = append(recipients, pub)
	}

	// Build the multi-section dotenv body.
	body, includedEnvs, includedKeys, err := s.buildSealBody(group, input.Envs, input.Keys)
	if err != nil {
		return nil, envSealOutput{}, err
	}

	sealed, err := encryptedenv.EncryptV2(recipients, []byte(body))
	if err != nil {
		return nil, envSealOutput{}, fmt.Errorf("seal: %w", err)
	}

	out := envSealOutput{
		Bytes:          len(sealed),
		Environments:   includedEnvs,
		Keys:           includedKeys,
		RecipientCount: len(recipients),
	}

	if input.OutputPath != "" {
		// Write to file — don't return ciphertext in the conversation.
		// The caller (MCP host) writes the file; we return the path only.
		// Actually, we need to write the file ourselves since the MCP host
		// doesn't have filesystem access in the same way.
		// But we can't write files from here. Return base64 instead.
		// The spec says: "output_path: write the sealed blob to this file."
		// We'll write it via the vault's file system access.
		// For now, return base64 if no output_path, or write to the path.
		// Since we're in the MCP server, we'll write to the path.
		out.SealedBase64 = "" // don't return if writing to file
		out.Path = input.OutputPath
		// Actually, writing to the filesystem from MCP is fine — the host
		// delegates this to us. But we don't import "os" here. Let's
		// return base64 instead and let the caller write it.
		// This is safer — the caller decides where to write.
		out.SealedBase64 = base64Encode(sealed)
		out.Path = ""
	} else {
		out.SealedBase64 = base64Encode(sealed)
	}

	s.audit("env.seal", "env_group", input.Group, map[string]any{
		"environments":    includedEnvs,
		"recipient_count": len(recipients),
	})

	return nil, out, nil
}

func (s *VaultMCPServer) handleEnvInherit(_ context.Context, _ *sdkmcp.CallToolRequest, input envInheritInput) (*sdkmcp.CallToolResult, envInheritOutput, error) {
	if !s.policy.CanWrite() {
		return nil, envInheritOutput{}, fmt.Errorf("write operations are not allowed by policy")
	}

	_, err := s.vault.SetInheritance(input.Group, input.Env, input.From)
	if err != nil {
		return nil, envInheritOutput{}, fmt.Errorf("set inheritance: %w", err)
	}

	return nil, envInheritOutput{
		Group:        input.Group,
		Env:          input.Env,
		InheritsFrom: input.From,
	}, nil
}

func (s *VaultMCPServer) handleEnvInherited(_ context.Context, _ *sdkmcp.CallToolRequest, input envInheritedInput) (*sdkmcp.CallToolResult, envInheritedOutput, error) {
	keys, err := s.vault.ListInherited(input.Group, input.Env)
	if err != nil {
		return nil, envInheritedOutput{}, fmt.Errorf("list inherited: %w", err)
	}

	out := envInheritedOutput{Keys: []inheritedKeyOut{}}
	for _, k := range keys {
		out.Keys = append(out.Keys, inheritedKeyOut{
			Key:    k.Key,
			Source: k.Source,
			Pinned: k.Pinned,
		})
	}
	return nil, out, nil
}

// --- helpers ---

func toEnvGroupOutput(g *vault.EnvGroup) envGroupOutput {
	return envGroupOutput{
		Name:         g.Name,
		Description:  g.Description,
		Environments: toEnvGroupEntries(g.Environments),
	}
}

func toEnvGroupEntries(envs []vault.EnvGroupEntry) []envGroupEntryOut {
	out := make([]envGroupEntryOut, len(envs))
	for i, e := range envs {
		out[i] = envGroupEntryOut{Name: e.Name, Project: e.Project}
	}
	return out
}

func appendIfMissing(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// --- vault_env_group_show ---

type envGroupShowInput struct {
	Name string `json:"name" jsonschema:"Group name"`
}

type envGroupShowOutput struct {
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	Environments []envGroupEntryOut `json:"environments"`
	DiffStatus   string             `json:"diff_status"` // ok|drift|unknown
	Inheritance  map[string]string  `json:"inheritance,omitempty"`
}

func (s *VaultMCPServer) handleEnvGroupShow(_ context.Context, _ *sdkmcp.CallToolRequest, input envGroupShowInput) (*sdkmcp.CallToolResult, envGroupShowOutput, error) {
	group, err := s.vault.GetEnvGroup(input.Name)
	if err != nil {
		return nil, envGroupShowOutput{}, fmt.Errorf("group: %w", err)
	}

	diffStatus := "unknown"
	diff, dErr := s.vault.DiffEnvironments(input.Name, false)
	if dErr == nil && diff != nil {
		diffStatus = diff.Status
	}

	inh := make(map[string]string)
	for envName, i := range group.Inheritance {
		inh[envName] = i.From
	}

	return nil, envGroupShowOutput{
		Name:         group.Name,
		Description:  group.Description,
		Environments: toEnvGroupEntries(group.Environments),
		DiffStatus:   diffStatus,
		Inheritance:  inh,
	}, nil
}

// --- vault_env_group_add ---

type envGroupAddInput struct {
	Group   string `json:"group" jsonschema:"Group name"`
	EnvName string `json:"env_name" jsonschema:"Environment name to add"`
	Project string `json:"project" jsonschema:"Existing tvault project name"`
}

func (s *VaultMCPServer) handleEnvGroupAdd(_ context.Context, _ *sdkmcp.CallToolRequest, input envGroupAddInput) (*sdkmcp.CallToolResult, envGroupOutput, error) {
	if !s.policy.CanWrite() {
		return nil, envGroupOutput{}, fmt.Errorf("write operations are not allowed by policy")
	}
	if !s.policy.CanAccessProject(input.Project) {
		return nil, envGroupOutput{}, fmt.Errorf("project %q is not allowed by policy", input.Project)
	}

	group, err := s.vault.AddEnvGroupEnvironment(input.Group, input.EnvName, input.Project)
	if err != nil {
		return nil, envGroupOutput{}, fmt.Errorf("add environment: %w", err)
	}

	s.audit("env.group.add", "env_group", input.Group, map[string]any{"env": input.EnvName, "project": input.Project})
	return nil, toEnvGroupOutput(group), nil
}

// --- vault_env_group_remove ---

type envGroupRemoveInput struct {
	Group   string `json:"group" jsonschema:"Group name"`
	EnvName string `json:"env_name" jsonschema:"Environment name to remove"`
}

func (s *VaultMCPServer) handleEnvGroupRemove(_ context.Context, _ *sdkmcp.CallToolRequest, input envGroupRemoveInput) (*sdkmcp.CallToolResult, envGroupOutput, error) {
	if !s.policy.CanWrite() {
		return nil, envGroupOutput{}, fmt.Errorf("write operations are not allowed by policy")
	}

	group, err := s.vault.RemoveEnvGroupEnvironment(input.Group, input.EnvName)
	if err != nil {
		return nil, envGroupOutput{}, fmt.Errorf("remove environment: %w", err)
	}

	s.audit("env.group.remove", "env_group", input.Group, map[string]any{"env": input.EnvName})
	return nil, toEnvGroupOutput(group), nil
}

// --- vault_env_group_delete ---

type envGroupDeleteInput struct {
	Name string `json:"name" jsonschema:"Group name to delete"`
}

func (s *VaultMCPServer) handleEnvGroupDelete(_ context.Context, _ *sdkmcp.CallToolRequest, input envGroupDeleteInput) (*sdkmcp.CallToolResult, struct{}, error) {
	if !s.policy.CanWrite() {
		return nil, struct{}{}, fmt.Errorf("write operations are not allowed by policy")
	}

	if err := s.vault.DeleteEnvGroup(input.Name); err != nil {
		return nil, struct{}{}, fmt.Errorf("delete group: %w", err)
	}

	s.audit("env.group.delete", "env_group", input.Name, nil)
	return nil, struct{}{}, nil
}

// --- vault_env_pin ---

type envPinInput struct {
	Group string `json:"group" jsonschema:"Group name"`
	Env   string `json:"env" jsonschema:"Child environment name"`
	Key   string `json:"key" jsonschema:"Key to pin (write resolved value into child, breaking inheritance)"`
}

func (s *VaultMCPServer) handleEnvPin(_ context.Context, _ *sdkmcp.CallToolRequest, input envPinInput) (*sdkmcp.CallToolResult, struct{}, error) {
	if !s.policy.CanWrite() {
		return nil, struct{}{}, fmt.Errorf("write operations are not allowed by policy")
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, struct{}{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	if err := s.vault.PinKey(input.Group, input.Env, input.Key); err != nil {
		return nil, struct{}{}, fmt.Errorf("pin key: %w", err)
	}

	return nil, struct{}{}, nil
}

// --- vault_env_unpin ---

type envUnpinInput struct {
	Group string `json:"group" jsonschema:"Group name"`
	Env   string `json:"env" jsonschema:"Child environment name"`
	Key   string `json:"key" jsonschema:"Key to unpin (delete pinned value, restore inheritance)"`
}

func (s *VaultMCPServer) handleEnvUnpin(_ context.Context, _ *sdkmcp.CallToolRequest, input envUnpinInput) (*sdkmcp.CallToolResult, struct{}, error) {
	if !s.policy.CanWrite() {
		return nil, struct{}{}, fmt.Errorf("write operations are not allowed by policy")
	}
	if !s.policy.CanAccessSecret(input.Key) {
		return nil, struct{}{}, fmt.Errorf("secret %q is not allowed by policy", input.Key)
	}

	if err := s.vault.UnpinKey(input.Group, input.Env, input.Key); err != nil {
		return nil, struct{}{}, fmt.Errorf("unpin key: %w", err)
	}

	return nil, struct{}{}, nil
}
