// Package sync reconciles a .env file with the vault.
//
// The model is: a .env file is a *projection* of the vault. You can pull
// (vault -> .env), push (.env -> vault), or mirror (both directions with
// conflict resolution). Sync never executes shell or interpolates other
// variables on its own -- interpolation is a separate layer (see
// internal/dotenv.Resolve).
package sync

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

// Direction tells Sync which way to push.
type Direction int

const (
	// Pull writes vault -> .env (vault is source of truth).
	Pull Direction = iota
	// Push writes .env -> vault (.env is source of truth).
	Push
	// Mirror reconciles both directions; conflicts are reported
	// in the result instead of auto-resolved.
	Mirror
)

func (d Direction) String() string {
	switch d {
	case Pull:
		return "pull"
	case Push:
		return "push"
	case Mirror:
		return "mirror"
	default:
		return "?"
	}
}

// ParseDirection parses a user-supplied direction string.
func ParseDirection(s string) (Direction, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pull", "vault->env", "vault-to-env":
		return Pull, nil
	case "push", "env->vault", "env-to-vault":
		return Push, nil
	case "mirror", "both", "two-way":
		return Mirror, nil
	default:
		return 0, fmt.Errorf("unknown sync direction %q (use pull|push|mirror)", s)
	}
}

// Conflict describes a key whose value differs between vault and .env.
type Conflict struct {
	Key        string
	VaultValue string
	EnvValue   string
	Resolution string // "kept-vault" | "kept-env" | "kept-existing"
}

// Result is the summary of a Sync call.
type Result struct {
	Direction    Direction
	Path         string
	Created      []string // keys created in target
	Updated      []string // keys updated in target
	Skipped      []string // keys that already existed and were not overwritten
	Unchanged    []string // keys whose value was already the same
	Conflicts    []Conflict
	EnvCreated   bool // true if the .env file was newly created
	ProjectName  string
	VaultEntries int
	EnvEntries   int
}

// Source is the read/write surface Sync needs from the vault. It is
// satisfied by *vault.Vault but defined here to keep the package
// dependency-free for testing.
type Source interface {
	GetAllSecrets(project string) (map[string]string, error)
	SetSecret(project, key, value string) error
}

// Sync reads the .env file at path (creating it if missing on pull) and
// reconciles it with the vault project. overwrite controls whether
// existing vault values are replaced on push.
func Sync(src Source, project, path string, dir Direction, overwrite bool) (Result, error) {
	res := Result{Direction: dir, Path: path, ProjectName: project}

	// Collect vault snapshot.
	vaultSecrets, err := src.GetAllSecrets(project)
	if err != nil {
		return res, fmt.Errorf("read vault: %w", err)
	}
	res.VaultEntries = len(vaultSecrets)

	switch dir {
	case Pull:
		return doPull(src, project, path, vaultSecrets, &res)
	case Push:
		return doPush(src, project, path, vaultSecrets, overwrite, &res)
	case Mirror:
		return doMirror(src, project, path, vaultSecrets, overwrite, &res)
	default:
		return res, fmt.Errorf("invalid direction %d", dir)
	}
}

func doPull(_ Source, _, path string, vaultSecrets map[string]string, res *Result) (Result, error) {
	// Read existing .env (if any) so we can detect Unchanged.
	existing, existingKeys, err := readEnv(path)
	if err != nil {
		return *res, err
	}
	res.EnvEntries = len(existingKeys)

	// Merge: vault wins. Preserve unknown .env keys (we don't delete
	// keys the user added manually).
	for k, v := range vaultSecrets {
		if old, ok := existing[k]; ok {
			if old == v {
				res.Unchanged = append(res.Unchanged, k)
			} else {
				res.Updated = append(res.Updated, k)
				existing[k] = v
			}
		} else {
			res.Created = append(res.Created, k)
			existing[k] = v
		}
	}

	if len(res.Created) == 0 && len(res.Updated) == 0 {
		// Nothing to write.
		return *res, nil
	}

	if err := writeEnv(path, existing, &res.EnvCreated); err != nil {
		return *res, err
	}
	sort.Strings(res.Created)
	sort.Strings(res.Updated)
	sort.Strings(res.Unchanged)
	return *res, nil
}

func doPush(src Source, project, path string, vaultSecrets map[string]string, overwrite bool, res *Result) (Result, error) {
	envSecrets, _, err := readEnv(path)
	if err != nil {
		return *res, err
	}
	res.EnvEntries = len(envSecrets)

	for k, v := range envSecrets {
		if old, ok := vaultSecrets[k]; ok {
			if old == v {
				res.Unchanged = append(res.Unchanged, k)
				continue
			}
			if !overwrite {
				res.Skipped = append(res.Skipped, k)
				continue
			}
			if err := src.SetSecret(project, k, v); err != nil {
				return *res, fmt.Errorf("set %s: %w", k, err)
			}
			res.Updated = append(res.Updated, k)
		} else {
			if err := src.SetSecret(project, k, v); err != nil {
				return *res, fmt.Errorf("set %s: %w", k, err)
			}
			res.Created = append(res.Created, k)
		}
	}

	sort.Strings(res.Created)
	sort.Strings(res.Updated)
	sort.Strings(res.Unchanged)
	sort.Strings(res.Skipped)
	return *res, nil
}

func doMirror(src Source, project, path string, vaultSecrets map[string]string, overwrite bool, res *Result) (Result, error) {
	envSecrets, _, err := readEnv(path)
	if err != nil {
		return *res, err
	}
	res.EnvEntries = len(envSecrets)

	allKeys := mergeKeys(vaultSecrets, envSecrets)
	sort.Strings(allKeys)

	for _, k := range allKeys {
		vv, inVault := vaultSecrets[k]
		ev, inEnv := envSecrets[k]
		if err := mirrorKey(src, project, k, vv, ev, inVault, inEnv, overwrite, res); err != nil {
			return *res, err
		}
	}

	return *res, nil
}

// mirrorKey reconciles a single key across the vault and the .env file.
// It mutates res in place and returns an error only on I/O failures.
func mirrorKey(src Source, project, k, vv, ev string, inVault, inEnv, overwrite bool, res *Result) error {
	switch {
	case inVault && !inEnv:
		// Vault has it, .env doesn't. Pull to .env.
		res.Created = append(res.Created, k)
	case !inVault && inEnv:
		// .env has it, vault doesn't. Push to vault.
		if err := src.SetSecret(project, k, ev); err != nil {
			return fmt.Errorf("set %s: %w", k, err)
		}
		res.Created = append(res.Created, k)
	case inVault && inEnv:
		if vv == ev {
			res.Unchanged = append(res.Unchanged, k)
			return nil
		}
		// Conflict: same key, different value. With --overwrite, .env
		// wins; without, the vault value is kept.
		if overwrite {
			if err := src.SetSecret(project, k, ev); err != nil {
				return fmt.Errorf("set %s: %w", k, err)
			}
			res.Updated = append(res.Updated, k)
			res.Conflicts = append(res.Conflicts, Conflict{
				Key: k, VaultValue: vv, EnvValue: ev, Resolution: "kept-env",
			})
		} else {
			res.Conflicts = append(res.Conflicts, Conflict{
				Key: k, VaultValue: vv, EnvValue: ev, Resolution: "kept-vault",
			})
			res.Skipped = append(res.Skipped, k)
		}
	}
	return nil
}

// mergeKeys returns the sorted union of the key sets of two maps. Used
// by doMirror to walk every key on either side.
func mergeKeys(a, b map[string]string) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		set[k] = struct{}{}
	}
	for k := range b {
		set[k] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

// ErrEmptyPath is returned when path is empty.
var ErrEmptyPath = errors.New("path is required")

func readEnv(path string) (map[string]string, map[string]struct{}, error) {
	if path == "" {
		return nil, nil, ErrEmptyPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, map[string]struct{}{}, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	// We use the existing parser but only the entries -- diagnostics are
	// ignored for sync (they don't change the result).
	parsed, err := dotenv.ParseBytes(path, data)
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string]string, len(parsed.Entries))
	keys := make(map[string]struct{}, len(parsed.Entries))
	for _, e := range parsed.Entries {
		out[e.Key] = e.Value
		keys[e.Key] = struct{}{}
	}
	return out, keys, nil
}

func writeEnv(path string, secrets map[string]string, created *bool) error {
	if path == "" {
		return ErrEmptyPath
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		*created = true
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# Generated by tvault sync pull\n")
	for _, k := range keys {
		v := secrets[k]
		// Use the parser's own escaping logic.
		fmt.Fprintf(&b, "%s=%s\n", k, formatDotenv(v))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// formatDotenv quotes values that need it. Same rules as parseValue.
func formatDotenv(v string) string {
	needsQuoting := strings.ContainsAny(v, "\"\\$\n\t #")
	if !needsQuoting {
		return v
	}
	escaped := strings.ReplaceAll(v, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	escaped = strings.ReplaceAll(escaped, "\n", "\\n")
	return "\"" + escaped + "\""
}
