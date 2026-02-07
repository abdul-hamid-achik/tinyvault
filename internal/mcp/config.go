package mcp

import (
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// AccessPolicy controls what the MCP server can expose.
type AccessPolicy struct {
	AccessMode         string   `yaml:"access_mode"`
	ProjectsAllow      []string `yaml:"projects_allow"`
	ProjectsDeny       []string `yaml:"projects_deny"`
	SecretsAllow       []string `yaml:"secrets_allow"`
	SecretsDeny        []string `yaml:"secrets_deny"`
	AllowExec          bool     `yaml:"allow_exec"`
	MaxReadsPerSession int      `yaml:"max_reads_per_session"`
	RedactOutput       bool     `yaml:"redact_output"`
}

// DefaultPolicy returns a permissive default policy.
func DefaultPolicy() *AccessPolicy {
	return &AccessPolicy{
		AccessMode:         "full",
		ProjectsAllow:      []string{"*"},
		ProjectsDeny:       nil,
		SecretsAllow:       []string{"*"},
		SecretsDeny:        nil,
		AllowExec:          true,
		MaxReadsPerSession: 50,
		RedactOutput:       true,
	}
}

// LoadPolicy reads an access policy from a YAML file.
// Returns nil, nil if the file does not exist.
func LoadPolicy(path string) (*AccessPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var policy AccessPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// CanAccessProject reports whether the policy allows access to the named project.
func (p *AccessPolicy) CanAccessProject(name string) bool {
	if matchesAny(name, p.ProjectsDeny) {
		return false
	}
	if len(p.ProjectsAllow) == 0 {
		return true
	}
	return matchesAny(name, p.ProjectsAllow)
}

// CanAccessSecret reports whether the policy allows access to the named secret key.
func (p *AccessPolicy) CanAccessSecret(key string) bool {
	if matchesAny(key, p.SecretsDeny) {
		return false
	}
	if len(p.SecretsAllow) == 0 {
		return true
	}
	return matchesAny(key, p.SecretsAllow)
}

// CanWrite reports whether the policy allows write operations.
func (p *AccessPolicy) CanWrite() bool {
	return p.AccessMode == "read-write" || p.AccessMode == "full"
}

// CanExec reports whether the policy allows command execution.
func (p *AccessPolicy) CanExec() bool {
	return p.AllowExec && p.AccessMode == "full"
}

// matchesAny returns true if name matches any of the glob patterns.
func matchesAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}
