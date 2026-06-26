package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/validation"
)

// EnvGroup is a named set of linked projects representing environments of the
// same application (e.g. production, preview, staging). It is pure metadata —
// no new crypto, no new buckets, no new key material. See SPEC-ENV-PROFILES.md.
type EnvGroup struct {
	Name         string                    `json:"name"`
	Description  string                    `json:"description,omitempty"`
	CreatedAt    string                    `json:"created_at"`
	UpdatedAt    string                    `json:"updated_at"`
	Environments []EnvGroupEntry           `json:"environments"`
	Inheritance  map[string]EnvInheritance `json:"inheritance,omitempty"`
}

// EnvGroupEntry maps an environment name to a tvault project.
type EnvGroupEntry struct {
	Name    string `json:"name"`
	Project string `json:"project"`
}

// EnvInheritance describes which environment a child inherits missing keys from.
type EnvInheritance struct {
	From string `json:"from"`
}

// EnvDiffKey reports the presence/status of a single key across all environments.
type EnvDiffKey struct {
	Key          string         `json:"key"`
	Environments []EnvDiffEntry `json:"environments"`
}

// EnvDiffEntry is the per-environment status for a key in a diff.
type EnvDiffEntry struct {
	Env     string `json:"env"`
	Present bool   `json:"present"`
	Status  string `json:"status"` // same|different|missing|local-only
}

// EnvDiff is the result of comparing key sets across environments in a group.
type EnvDiff struct {
	Group  string       `json:"group"`
	Status string       `json:"status"` // ok|drift
	Keys   []EnvDiffKey `json:"keys"`
}

// PromoteResult records the outcome of a promote operation.
type PromoteResult struct {
	Promoted []PromotedKey `json:"promoted"`
	Skipped  []SkippedKey  `json:"skipped"`
}

// PromotedKey records a single key that was promoted.
type PromotedKey struct {
	Key         string `json:"key"`
	FromVersion int    `json:"from_version"`
	ToVersion   int    `json:"to_version"`
}

// SkippedKey records a key that was not promoted and why.
type SkippedKey struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// InheritedKey reports whether a key is local, inherited, or missing.
type InheritedKey struct {
	Key    string `json:"key"`
	Source string `json:"source"` // local|inherited:<env>|missing
	Pinned bool   `json:"pinned"`
}

const (
	configGroupPrefix = "group:"
	statusOK          = "ok"
	statusDrift       = "drift"
	statusSame        = "same"
	statusDifferent   = "different"
	statusMissing     = "missing"
	statusLocalOnly   = "local-only"
)

// validateEnvGroupInput checks the group name and environment entries for
// structural validity (non-empty, unique names).
func validateEnvGroupInput(name string, environments []EnvGroupEntry) error {
	if name == "" {
		return fmt.Errorf("group name is required")
	}
	if len(environments) == 0 {
		return fmt.Errorf("at least one environment is required")
	}
	seen := make(map[string]bool)
	for _, e := range environments {
		if e.Name == "" {
			return fmt.Errorf("environment name is required")
		}
		if e.Project == "" {
			return fmt.Errorf("project name is required for environment %q", e.Name)
		}
		if seen[e.Name] {
			return fmt.Errorf("duplicate environment name %q", e.Name)
		}
		seen[e.Name] = true
	}
	return nil
}

// checkProjectNotInOtherGroups verifies that none of the environments' projects
// are already linked to a different group (unless force is true).
func (v *Vault) checkProjectNotInOtherGroups(name string, environments []EnvGroupEntry, force bool) error {
	existingGroups, err := v.listEnvGroupsRaw()
	if err != nil {
		return fmt.Errorf("list existing groups: %w", err)
	}
	for _, eg := range existingGroups {
		if eg.Name == name {
			continue // same group, force mode
		}
		for _, e := range environments {
			for _, ee := range eg.Environments {
				if ee.Project == e.Project && !force {
					return fmt.Errorf("project %q already in group %q (use --force to re-link)", e.Project, eg.Name)
				}
			}
		}
	}
	return nil
}

// CreateEnvGroup creates a new environment group linking multiple projects.
// Each project must already exist. Environment names must be unique within
// the group. A project can belong to at most one group unless force is true.
func (v *Vault) CreateEnvGroup(name, description string, environments []EnvGroupEntry, force bool) (*EnvGroup, error) {
	if err := validateEnvGroupInput(name, environments); err != nil {
		return nil, err
	}

	// Validate all projects exist.
	for _, e := range environments {
		if _, err := v.store.GetProjectByName(e.Project); err != nil {
			return nil, fmt.Errorf("project %q: %w", e.Project, mapStoreError(err))
		}
	}

	// Check for existing group.
	key := configGroupPrefix + name
	if existing, err := v.store.GetConfig(key); err == nil && existing != "" && !force {
		return nil, fmt.Errorf("group %q already exists", name)
	}

	// Check that projects aren't already in another group.
	if err := v.checkProjectNotInOtherGroups(name, environments, force); err != nil {
		return nil, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	group := &EnvGroup{
		Name:         name,
		Description:  description,
		CreatedAt:    now,
		UpdatedAt:    now,
		Environments: environments,
		Inheritance:  make(map[string]EnvInheritance),
	}

	if err := v.saveEnvGroup(group); err != nil {
		return nil, err
	}

	return group, nil
}

// GetEnvGroup retrieves a group by name.
func (v *Vault) GetEnvGroup(name string) (*EnvGroup, error) {
	raw, err := v.store.GetConfig(configGroupPrefix + name)
	if err != nil {
		return nil, fmt.Errorf("group %q: %w", name, ErrGroupNotFound)
	}
	var group EnvGroup
	if err := json.Unmarshal([]byte(raw), &group); err != nil {
		return nil, fmt.Errorf("unmarshal group %q: %w", name, err)
	}
	return &group, nil
}

// ListEnvGroups returns all environment groups.
func (v *Vault) ListEnvGroups() ([]EnvGroup, error) {
	return v.listEnvGroupsRaw()
}

// listEnvGroupsRaw reads all groups from the config bucket.
func (v *Vault) listEnvGroupsRaw() ([]EnvGroup, error) {
	// ConfigStore only supports GetConfig/SetConfig/DeleteConfig — there is
	// no list-keys. We work around this by listing all projects and checking
	// each project's membership, but that's O(projects×groups). Instead, we
	// maintain a group index key that lists all group names.
	indexRaw, err := v.store.GetConfig(configGroupPrefix + "_index")
	if err != nil {
		return nil, nil //nolint:nilerr // no groups yet (key doesn't exist)
	}
	if indexRaw == "" {
		return nil, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(indexRaw), &names); err != nil {
		return nil, fmt.Errorf("unmarshal group index: %w", err)
	}
	groups := make([]EnvGroup, 0, len(names))
	for _, name := range names {
		g, err := v.GetEnvGroup(name)
		if err != nil {
			continue // stale index entry, skip
		}
		groups = append(groups, *g)
	}
	return groups, nil
}

// saveEnvGroup writes a group and updates the group index.
func (v *Vault) saveEnvGroup(group *EnvGroup) error {
	data, err := json.Marshal(group)
	if err != nil {
		return fmt.Errorf("marshal group: %w", err)
	}
	if err := v.store.SetConfig(configGroupPrefix+group.Name, string(data)); err != nil {
		return fmt.Errorf("save group: %w", err)
	}

	// Update the index.
	names, _ := v.store.GetConfig(configGroupPrefix + "_index") //nolint:errcheck // best-effort
	var existing []string
	if names != "" {
		_ = json.Unmarshal([]byte(names), &existing) //nolint:errcheck // best-effort
	}
	found := false
	for _, n := range existing {
		if n == group.Name {
			found = true
			break
		}
	}
	if !found {
		existing = append(existing, group.Name)
		sort.Strings(existing)
		idxData, _ := json.Marshal(existing)                               //nolint:errcheck // best-effort
		_ = v.store.SetConfig(configGroupPrefix+"_index", string(idxData)) //nolint:errcheck // best-effort
	}
	return nil
}

// AddEnvGroupEnvironment adds an environment to an existing group.
func (v *Vault) AddEnvGroupEnvironment(groupName, envName, projectName string) (*EnvGroup, error) {
	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return nil, err
	}

	// Validate project exists.
	if _, pErr := v.store.GetProjectByName(projectName); pErr != nil {
		return nil, fmt.Errorf("project %q: %w", projectName, mapStoreError(pErr))
	}

	// Check env name is unique within the group.
	for _, e := range group.Environments {
		if e.Name == envName {
			return nil, fmt.Errorf("environment %q already exists in group %q", envName, groupName)
		}
	}

	// Check project isn't in another group.
	existingGroups, err := v.listEnvGroupsRaw()
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	for _, eg := range existingGroups {
		if eg.Name == groupName {
			continue
		}
		for _, ee := range eg.Environments {
			if ee.Project == projectName {
				return nil, fmt.Errorf("project %q already in group %q", projectName, eg.Name)
			}
		}
	}

	group.Environments = append(group.Environments, EnvGroupEntry{
		Name:    envName,
		Project: projectName,
	})
	group.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := v.saveEnvGroup(group); err != nil {
		return nil, err
	}
	return group, nil
}

// RemoveEnvGroupEnvironment removes an environment from a group.
// It does not delete the project.
func (v *Vault) RemoveEnvGroupEnvironment(groupName, envName string) (*EnvGroup, error) {
	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return nil, err
	}

	found := false
	filtered := group.Environments[:0]
	for _, e := range group.Environments {
		if e.Name == envName {
			found = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !found {
		return nil, fmt.Errorf("environment %q not found in group %q", envName, groupName)
	}

	group.Environments = filtered
	// Remove inheritance config for the removed env.
	if group.Inheritance != nil {
		delete(group.Inheritance, envName)
	}
	group.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := v.saveEnvGroup(group); err != nil {
		return nil, err
	}
	return group, nil
}

// DeleteEnvGroup deletes a group entirely. Projects are untouched.
func (v *Vault) DeleteEnvGroup(name string) error {
	if err := v.store.DeleteConfig(configGroupPrefix + name); err != nil {
		return fmt.Errorf("delete group %q: %w", name, err)
	}

	// Update the index.
	names, _ := v.store.GetConfig(configGroupPrefix + "_index") //nolint:errcheck // best-effort
	if names == "" {
		return nil
	}
	var existing []string
	if err := json.Unmarshal([]byte(names), &existing); err != nil {
		return nil //nolint:nilerr // index is corrupt; nothing to update
	}
	filtered := existing[:0]
	for _, n := range existing {
		if n != name {
			filtered = append(filtered, n)
		}
	}
	if len(filtered) == 0 {
		_ = v.store.DeleteConfig(configGroupPrefix + "_index") //nolint:errcheck // best-effort
	} else {
		idxData, _ := json.Marshal(filtered)                               //nolint:errcheck // best-effort
		_ = v.store.SetConfig(configGroupPrefix+"_index", string(idxData)) //nolint:errcheck // best-effort
	}
	return nil
}

// resolveEnvProject returns the project name for a given environment in a group.
func (v *Vault) resolveEnvProject(group *EnvGroup, envName string) (string, error) {
	for _, e := range group.Environments {
		if e.Name == envName {
			return e.Project, nil
		}
	}
	return "", fmt.Errorf("environment %q not found in group %q", envName, group.Name)
}

// buildDiffEntries builds the per-environment entries for a single key in a
// diff. Returns the entries and whether this key has drift (missing in some
// envs, or different values).
//
//nolint:gocognit,gocyclo // inherently complex: per-env, per-key comparison with value diffing
func (v *Vault) buildDiffEntries(
	key string,
	envs []EnvGroupEntry,
	envKeySets [][]string,
	envValueMaps []map[string]string,
	compareValues bool,
) ([]EnvDiffEntry, bool) {
	entries := make([]EnvDiffEntry, len(envs))
	anyMissing := false
	anyPresent := false
	var firstValue string
	firstSet := false

	for i, e := range envs {
		present := false
		for _, k := range envKeySets[i] {
			if k == key {
				present = true
				break
			}
		}
		entries[i] = EnvDiffEntry{Env: e.Name, Present: present}
		if present {
			anyPresent = true
			if compareValues {
				val := envValueMaps[i][key]
				switch {
				case !firstSet:
					firstValue = val
					firstSet = true
					entries[i].Status = statusSame
				case val == firstValue:
					entries[i].Status = statusSame
				default:
					entries[i].Status = statusDifferent
				}
			} else {
				entries[i].Status = statusLocalOnly
			}
		} else {
			anyMissing = true
			entries[i].Status = statusMissing
		}
	}

	hasDrift := anyMissing && anyPresent

	if compareValues {
		anyDifferent := false
		for _, e := range entries {
			if e.Status == statusDifferent {
				anyDifferent = true
				break
			}
		}
		if anyDifferent {
			for i := range entries {
				if entries[i].Present && entries[i].Status == statusSame {
					entries[i].Status = statusDifferent
				}
			}
			hasDrift = true
		}
	}

	return entries, hasDrift
}

// DiffEnvironments compares key sets across all environments in a group.
// When compareValues is true, it also reports whether values are same or
// different (metadata only — values are never returned). This requires the
// vault to be unlocked.
func (v *Vault) DiffEnvironments(groupName string, compareValues bool) (*EnvDiff, error) {
	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return nil, err
	}

	if len(group.Environments) == 0 {
		return &EnvDiff{Group: groupName, Status: statusOK, Keys: []EnvDiffKey{}}, nil
	}

	// Collect key sets for each environment.
	envKeySets := make([][]string, len(group.Environments))
	allKeys := make(map[string]bool)
	for i, e := range group.Environments {
		keys, err := v.ListSecrets(e.Project)
		if err != nil {
			return nil, fmt.Errorf("list secrets for %s: %w", e.Project, err)
		}
		envKeySets[i] = keys
		for _, k := range keys {
			allKeys[k] = true
		}
	}

	// If comparing values, get the value maps.
	envValueMaps := make([]map[string]string, len(group.Environments))
	if compareValues {
		if err := v.requireUnlocked(); err != nil {
			return nil, err
		}
		for i, e := range group.Environments {
			vals, err := v.GetAllSecrets(e.Project)
			if err != nil {
				return nil, fmt.Errorf("get secrets for %s: %w", e.Project, err)
			}
			envValueMaps[i] = vals
		}
	}

	// Build sorted key list.
	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	diffKeys := make([]EnvDiffKey, 0, len(sortedKeys))
	hasDrift := false

	for _, key := range sortedKeys {
		entries, keyHasDrift := v.buildDiffEntries(key, group.Environments, envKeySets, envValueMaps, compareValues)
		if keyHasDrift {
			hasDrift = true
		}
		diffKeys = append(diffKeys, EnvDiffKey{
			Key:          key,
			Environments: entries,
		})
	}

	status := statusOK
	if hasDrift {
		status = statusDrift
	}

	return &EnvDiff{
		Group:  groupName,
		Status: status,
		Keys:   diffKeys,
	}, nil
}

// Promote copies secret values from one environment to another within a group.
// The value is decrypted from the source project and re-encrypted into the
// target project, creating a new version (the prior value is archived).
// When dryRun is true, no writes occur — only the report is returned.
//
//nolint:gocognit,gocyclo // cross-DEK crypto + audit + dry-run branching
func (v *Vault) Promote(groupName, fromEnv, toEnv string, keys []string, all, dryRun bool) (*PromoteResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}

	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return nil, err
	}

	fromProject, err := v.resolveEnvProject(group, fromEnv)
	if err != nil {
		return nil, err
	}
	toProject, err := v.resolveEnvProject(group, toEnv)
	if err != nil {
		return nil, err
	}

	if fromProject == toProject {
		return nil, fmt.Errorf("source and target environments are the same project")
	}

	// Determine the key set to promote.
	var keyList []string
	switch {
	case all:
		fromProj, ferr := v.store.GetProjectByName(fromProject)
		if ferr != nil {
			return nil, fmt.Errorf("get source project: %w", mapStoreError(ferr))
		}
		fromKeys, lerr := v.store.ListSecretKeys(fromProj.ID)
		if lerr != nil {
			return nil, fmt.Errorf("list source secrets: %w", lerr)
		}
		keyList = fromKeys
	case len(keys) > 0:
		keyList = keys
	default:
		return nil, fmt.Errorf("no keys specified (use --all or provide key names)")
	}

	result := &PromoteResult{
		Promoted: []PromotedKey{},
		Skipped:  []SkippedKey{},
	}

	// Resolve source and target projects for crypto.
	srcProj, err := v.store.GetProjectByName(fromProject)
	if err != nil {
		return nil, mapStoreError(err)
	}
	dstProj, err := v.store.GetProjectByName(toProject)
	if err != nil {
		return nil, mapStoreError(err)
	}

	srcDEK, err := v.getDecryptedDEK(srcProj.ID)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(srcDEK)

	dstDEK, err := v.getDecryptedDEK(dstProj.ID)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(dstDEK)

	for _, key := range keyList {
		// Get the value from the source project (internal — no lock).
		entry, serr := v.store.GetSecret(srcProj.ID, key)
		if serr != nil {
			result.Skipped = append(result.Skipped, SkippedKey{
				Key:    key,
				Reason: fmt.Sprintf("not found in %s: %v", fromEnv, mapStoreError(serr)),
			})
			continue
		}

		plaintext, derr := crypto.Decrypt(srcDEK, entry.EncryptedValue)
		if derr != nil {
			result.Skipped = append(result.Skipped, SkippedKey{
				Key:    key,
				Reason: fmt.Sprintf("decrypt: %v", derr),
			})
			continue
		}

		if dryRun {
			result.Promoted = append(result.Promoted, PromotedKey{
				Key:         key,
				FromVersion: entry.Version,
				ToVersion:   0,
			})
			crypto.ZeroBytes(plaintext)
			continue
		}

		// Encrypt into target project.
		reEncrypted, eerr := crypto.Encrypt(dstDEK, plaintext)
		crypto.ZeroBytes(plaintext)
		if eerr != nil {
			result.Skipped = append(result.Skipped, SkippedKey{
				Key:    key,
				Reason: fmt.Sprintf("re-encrypt: %v", eerr),
			})
			continue
		}

		now := time.Now().UTC()
		newEntry := &store.SecretEntry{
			EncryptedValue: reEncrypted,
			Version:        1,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if werr := v.store.SetSecret(dstProj.ID, key, newEntry); werr != nil {
			result.Skipped = append(result.Skipped, SkippedKey{
				Key:    key,
				Reason: fmt.Sprintf("set in %s: %v", toEnv, werr),
			})
			continue
		}

		result.Promoted = append(result.Promoted, PromotedKey{
			Key:         key,
			FromVersion: entry.Version,
			ToVersion:   newEntry.Version,
		})

		// Audit the promote.
		//nolint:errcheck // audit is best-effort
		v.AppendAudit(makeAuditEntry("secret.promote", "secret", key, map[string]any{
			"group":    groupName,
			"from_env": fromEnv,
			"to_env":   toEnv,
		}))
	}

	return result, nil
}

// SetInheritance configures key inheritance for an environment.
// The child environment resolves missing keys from the base environment at
// read time.
func (v *Vault) SetInheritance(groupName, envName, fromEnv string) (*EnvGroup, error) {
	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return nil, err
	}

	// Validate both envs exist.
	if _, err := v.resolveEnvProject(group, envName); err != nil {
		return nil, err
	}
	if _, err := v.resolveEnvProject(group, fromEnv); err != nil {
		return nil, err
	}

	if envName == fromEnv {
		return nil, fmt.Errorf("an environment cannot inherit from itself")
	}

	if group.Inheritance == nil {
		group.Inheritance = make(map[string]EnvInheritance)
	}
	group.Inheritance[envName] = EnvInheritance{From: fromEnv}
	group.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := v.saveEnvGroup(group); err != nil {
		return nil, err
	}

	//nolint:errcheck // audit is best-effort
	v.AppendAudit(makeAuditEntry("env.inherit", "env_group", groupName, map[string]any{
		"env":  envName,
		"from": fromEnv,
	}))

	return group, nil
}

// ResolveKey resolves a key through the inheritance chain. It returns the
// value and the source environment name. If the key exists in the child
// project, that value is returned. If not, it falls back to the base
// environment. If the key is not found anywhere, it returns ErrSecretNotFound.
func (v *Vault) ResolveKey(groupName, envName, key string) (value, sourceEnv string, retErr error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := v.requireUnlocked(); err != nil {
		return "", "", err
	}

	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return "", "", err
	}

	// Try the child project first.
	childProject, err := v.resolveEnvProject(group, envName)
	if err != nil {
		return "", "", err
	}

	childVal, childErr := v.getSecretInternal(childProject, key)
	if childErr == nil {
		return childVal, envName, nil
	}

	// If not found in child, check inheritance.
	if group.Inheritance != nil {
		if inh, ok := group.Inheritance[envName]; ok {
			baseProject, err := v.resolveEnvProject(group, inh.From)
			if err != nil {
				return "", "", err
			}
			baseVal, baseErr := v.getSecretInternal(baseProject, key)
			if baseErr == nil {
				return baseVal, inh.From, nil
			}
		}
	}

	return "", "", ErrSecretNotFound
}

// getSecretInternal decrypts a secret without acquiring the vault mutex — the
// caller must already hold the appropriate lock.
func (v *Vault) getSecretInternal(projectName, key string) (string, error) {
	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return "", mapStoreError(err)
	}
	entry, err := v.store.GetSecret(project.ID, key)
	if err != nil {
		return "", mapStoreError(err)
	}
	dek, err := v.getDecryptedDEK(project.ID)
	if err != nil {
		return "", err
	}
	plaintext, err := crypto.Decrypt(dek, entry.EncryptedValue)
	crypto.ZeroBytes(dek)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(plaintext), nil
}

// setSecretInternal encrypts and stores a secret without acquiring the vault
// mutex — the caller must already hold the appropriate lock.
func (v *Vault) setSecretInternal(projectName, key, value string) error {
	if err := validation.SecretKey(key); err != nil {
		return fmt.Errorf("invalid secret key: %w", err)
	}
	project, err := v.store.GetProjectByName(projectName)
	if err != nil {
		return mapStoreError(err)
	}
	dek, err := v.getDecryptedDEK(project.ID)
	if err != nil {
		return err
	}
	encryptedValue, err := crypto.Encrypt(dek, []byte(value))
	crypto.ZeroBytes(dek)
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}
	now := time.Now().UTC()
	entry := &store.SecretEntry{
		EncryptedValue: encryptedValue,
		Version:        1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return mapStoreError(v.store.SetSecret(project.ID, key, entry))
}

// PinKey writes the current resolved value of a key into the child project,
// breaking inheritance for that key only.
func (v *Vault) PinKey(groupName, envName, key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.requireUnlocked(); err != nil {
		return err
	}

	// Resolve the value through the inheritance chain using internal helpers
	// (no lock re-acquisition).
	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return err
	}

	childProject, err := v.resolveEnvProject(group, envName)
	if err != nil {
		return err
	}

	value, _, err := v.resolveKeyInternal(group, envName, childProject, key)
	if err != nil {
		return err
	}

	if err := v.setSecretInternal(childProject, key, value); err != nil {
		return err
	}

	//nolint:errcheck // audit is best-effort
	v.AppendAudit(makeAuditEntry("secret.pin", "secret", key, map[string]any{
		"group": groupName,
		"env":   envName,
	}))

	return nil
}

// resolveKeyInternal is the lock-free version of ResolveKey — the caller
// must already hold the appropriate lock.
func (v *Vault) resolveKeyInternal(group *EnvGroup, envName, childProject, key string) (string, string, error) {
	childVal, childErr := v.getSecretInternal(childProject, key)
	if childErr == nil {
		return childVal, envName, nil
	}

	if group.Inheritance != nil {
		if inh, ok := group.Inheritance[envName]; ok {
			baseProject, err := v.resolveEnvProject(group, inh.From)
			if err != nil {
				return "", "", err
			}
			baseVal, baseErr := v.getSecretInternal(baseProject, key)
			if baseErr == nil {
				return baseVal, inh.From, nil
			}
		}
	}

	return "", "", ErrSecretNotFound
}

// UnpinKey deletes the pinned value from the child project, restoring
// inheritance for that key.
func (v *Vault) UnpinKey(groupName, envName, key string) error {
	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return err
	}
	project, err := v.resolveEnvProject(group, envName)
	if err != nil {
		return err
	}

	if err := v.DeleteSecret(project, key); err != nil {
		return err
	}

	//nolint:errcheck // audit is best-effort
	v.AppendAudit(makeAuditEntry("secret.unpin", "secret", key, map[string]any{
		"group": groupName,
		"env":   envName,
	}))

	return nil
}

// ListInherited shows which keys in an environment are inherited vs local (pinned).
//
//nolint:gocognit,gocyclo // child+base key set merging with inheritance status
func (v *Vault) ListInherited(groupName, envName string) ([]InheritedKey, error) {
	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return nil, err
	}

	childProject, err := v.resolveEnvProject(group, envName)
	if err != nil {
		return nil, err
	}

	// Get child keys.
	childKeys, err := v.ListSecrets(childProject)
	if err != nil {
		return nil, fmt.Errorf("list child secrets: %w", err)
	}
	childSet := make(map[string]bool, len(childKeys))
	for _, k := range childKeys {
		childSet[k] = true
	}

	// Get base keys if inheritance is configured.
	var baseSet map[string]bool
	baseEnvName := ""
	if group.Inheritance != nil {
		if inh, ok := group.Inheritance[envName]; ok {
			baseEnvName = inh.From
			baseProject, err := v.resolveEnvProject(group, inh.From)
			if err == nil {
				baseKeys, err := v.ListSecrets(baseProject)
				if err == nil {
					baseSet = make(map[string]bool, len(baseKeys))
					for _, k := range baseKeys {
						baseSet[k] = true
					}
				}
			}
		}
	}

	// Collect all keys.
	allKeys := make(map[string]bool)
	for k := range childSet {
		allKeys[k] = true
	}
	for k := range baseSet {
		allKeys[k] = true
	}

	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	result := make([]InheritedKey, 0, len(sortedKeys))
	for _, key := range sortedKeys {
		ik := InheritedKey{Key: key}
		switch {
		case childSet[key]:
			ik.Source = "local"
			ik.Pinned = true
		case baseSet[key]:
			ik.Source = "inherited:" + baseEnvName
			ik.Pinned = false
		default:
			ik.Source = "missing"
		}
		result = append(result, ik)
	}

	return result, nil
}

// makeAuditEntry creates an AuditEntry with the current timestamp.
func makeAuditEntry(action, resourceType, name string, metadata map[string]any) *store.AuditEntry {
	return &store.AuditEntry{
		Action:       action,
		ResourceType: resourceType,
		ResourceName: name,
		Timestamp:    time.Now().UTC(),
		Metadata:     metadata,
	}
}

// ErrGroupNotFound is returned when an environment group cannot be found.
var ErrGroupNotFound = errors.New("environment group not found")
