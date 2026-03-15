package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

type listEnvFilesInput struct {
	Directory   string `json:"directory,omitempty" jsonschema:"Directory to scan for dotenv files. Default: current directory."`
	Environment string `json:"environment,omitempty" jsonschema:"Environment name used to recommend a default dotenv chain, such as production."`
}

type envFileInfo struct {
	DiagnosticCount int    `json:"diagnostic_count"`
	KeyCount        int    `json:"key_count"`
	Path            string `json:"path"`
	Suggested       bool   `json:"suggested,omitempty"`
}

type listEnvFilesOutput struct {
	Directory      string        `json:"directory"`
	Environment    string        `json:"environment,omitempty"`
	Files          []envFileInfo `json:"files"`
	SuggestedFiles []string      `json:"suggested_files"`
}

type previewEnvImportInput struct {
	Project     string   `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Directory   string   `json:"directory,omitempty" jsonschema:"Directory to scan for dotenv files when files are not explicitly provided. Default: current directory."`
	Files       []string `json:"files,omitempty" jsonschema:"Explicit dotenv files to merge in order. If omitted the default chain for the directory and environment is used."`
	Environment string   `json:"environment,omitempty" jsonschema:"Environment name used for the default dotenv chain, such as production."`
	Overwrite   bool     `json:"overwrite,omitempty" jsonschema:"Whether existing vault secrets should be overwritten."`
}

type envImportKeyPreview struct {
	Action     string `json:"action"`
	Key        string `json:"key"`
	SourcePath string `json:"source_path"`
}

type previewEnvImportOutput struct {
	BlockedCount    int                   `json:"blocked_count"`
	CreateCount     int                   `json:"create_count"`
	DiagnosticCount int                   `json:"diagnostic_count"`
	Diagnostics     []dotenv.Diagnostic   `json:"diagnostics"`
	Files           []string              `json:"files"`
	Keys            []envImportKeyPreview `json:"keys"`
	BlockedKeys     []string              `json:"blocked_keys"`
	OverwriteCount  int                   `json:"overwrite_count"`
	Project         string                `json:"project"`
	SkipCount       int                   `json:"skip_count"`
}

type importEnvFilesInput = previewEnvImportInput

type importEnvFilesOutput struct {
	BlockedCount    int                 `json:"blocked_count"`
	BlockedKeys     []string            `json:"blocked_keys"`
	CreateCount     int                 `json:"create_count"`
	DiagnosticCount int                 `json:"diagnostic_count"`
	Diagnostics     []dotenv.Diagnostic `json:"diagnostics"`
	Files           []string            `json:"files"`
	ImportedKeys    []string            `json:"imported_keys"`
	OverwriteCount  int                 `json:"overwrite_count"`
	Project         string              `json:"project"`
	SkippedKeys     []string            `json:"skipped_keys"`
	SkipCount       int                 `json:"skip_count"`
}

func (s *VaultMCPServer) registerImportEnvTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_list_env_files",
		Description: "Discover safe dotenv-family files like .env, .env.local, and .env.production without returning any secret values.",
	}, s.handleListEnvFiles)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_preview_env_import",
		Description: "Preview a dotenv import into the vault. Returns only file paths, key names, counts, and diagnostics - never secret values.",
	}, s.handlePreviewEnvImport)

	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name:        "vault_import_env_files",
		Description: "Import dotenv files into the vault without exposing secret values to the AI. Use vault_preview_env_import first when possible.",
	}, s.handleImportEnvFiles)
}

func (s *VaultMCPServer) handleListEnvFiles(_ context.Context, _ *sdkmcp.CallToolRequest, input listEnvFilesInput) (*sdkmcp.CallToolResult, listEnvFilesOutput, error) {
	directory := input.Directory
	if directory == "" {
		directory = "."
	}

	files, err := dotenv.Discover(directory)
	if err != nil {
		return nil, listEnvFilesOutput{}, fmt.Errorf("discover dotenv files: %w", err)
	}

	suggested := dotenv.DefaultSelection(files, input.Environment)
	suggestedSet := make(map[string]bool, len(suggested))
	for _, file := range suggested {
		suggestedSet[file.Path] = true
	}

	infos := make([]envFileInfo, 0, len(files))
	for _, file := range files {
		parsed, err := dotenv.ParseFile(file.Path)
		diagnosticCount := 0
		keyCount := 0
		if err != nil {
			diagnosticCount = 1
		} else {
			diagnosticCount = len(parsed.Diagnostics)
			keyCount = len(parsed.Entries)
		}

		infos = append(infos, envFileInfo{
			DiagnosticCount: diagnosticCount,
			KeyCount:        keyCount,
			Path:            file.Path,
			Suggested:       suggestedSet[file.Path],
		})
	}

	if infos == nil {
		infos = []envFileInfo{}
	}

	return nil, listEnvFilesOutput{
		Directory:      directory,
		Environment:    input.Environment,
		Files:          infos,
		SuggestedFiles: importEnvPaths(suggested),
	}, nil
}

func (s *VaultMCPServer) handlePreviewEnvImport(_ context.Context, _ *sdkmcp.CallToolRequest, input previewEnvImportInput) (*sdkmcp.CallToolResult, previewEnvImportOutput, error) {
	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, previewEnvImportOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}

	plan, err := s.buildEnvImportPlan(project, input.Files, input.Directory, input.Environment, input.Overwrite)
	if err != nil {
		return nil, previewEnvImportOutput{}, err
	}

	output := previewEnvImportOutput{
		DiagnosticCount: len(plan.Diagnostics),
		Diagnostics:     append([]dotenv.Diagnostic{}, plan.Diagnostics...),
		Files:           plan.Files,
		Keys:            []envImportKeyPreview{},
		BlockedKeys:     []string{},
		Project:         project,
	}

	for _, entry := range plan.Entries {
		if !s.policy.CanAccessSecret(entry.Key) {
			output.BlockedCount++
			output.BlockedKeys = append(output.BlockedKeys, entry.Key)
			continue
		}

		output.Keys = append(output.Keys, envImportKeyPreview{
			Action:     string(entry.Action),
			Key:        entry.Key,
			SourcePath: entry.SourcePath,
		})

		switch entry.Action {
		case dotenv.ActionCreate:
			output.CreateCount++
		case dotenv.ActionOverwrite:
			output.OverwriteCount++
		case dotenv.ActionSkip:
			output.SkipCount++
		}
	}

	return nil, output, nil
}

func (s *VaultMCPServer) handleImportEnvFiles(_ context.Context, _ *sdkmcp.CallToolRequest, input importEnvFilesInput) (*sdkmcp.CallToolResult, importEnvFilesOutput, error) {
	if !s.policy.CanWrite() {
		return nil, importEnvFilesOutput{}, fmt.Errorf("write operations are not allowed by policy (access_mode: %s)", s.policy.AccessMode)
	}

	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, importEnvFilesOutput{}, fmt.Errorf("project %q is not allowed by policy", project)
	}

	plan, err := s.buildEnvImportPlan(project, input.Files, input.Directory, input.Environment, input.Overwrite)
	if err != nil {
		return nil, importEnvFilesOutput{}, err
	}

	output := importEnvFilesOutput{
		BlockedKeys:     []string{},
		DiagnosticCount: len(plan.Diagnostics),
		Diagnostics:     append([]dotenv.Diagnostic{}, plan.Diagnostics...),
		Files:           plan.Files,
		ImportedKeys:    []string{},
		Project:         project,
		SkippedKeys:     []string{},
	}

	for _, entry := range plan.Entries {
		if !s.policy.CanAccessSecret(entry.Key) {
			output.BlockedCount++
			output.BlockedKeys = append(output.BlockedKeys, entry.Key)
			continue
		}

		if entry.Action == dotenv.ActionSkip {
			output.SkipCount++
			output.SkippedKeys = append(output.SkippedKeys, entry.Key)
			continue
		}

		if err := s.vault.SetSecret(project, entry.Key, entry.Value); err != nil {
			return nil, importEnvFilesOutput{}, fmt.Errorf("set secret %s: %w", entry.Key, err)
		}

		output.ImportedKeys = append(output.ImportedKeys, entry.Key)
		if entry.Action == dotenv.ActionCreate {
			output.CreateCount++
		} else {
			output.OverwriteCount++
		}
	}

	s.audit("env.import", "env", project, map[string]any{
		"blocked_count":   output.BlockedCount,
		"created_count":   output.CreateCount,
		"directory":       defaultImportDirectory(input.Directory),
		"environment":     input.Environment,
		"files":           output.Files,
		"overwrite_count": output.OverwriteCount,
		"skip_count":      output.SkipCount,
	})

	return nil, output, nil
}

func (s *VaultMCPServer) buildEnvImportPlan(project string, explicitFiles []string, directory, environment string, overwrite bool) (dotenv.ImportPlan, error) {
	files, err := resolveEnvImportFiles(explicitFiles, directory, environment)
	if err != nil {
		return dotenv.ImportPlan{}, err
	}

	existingKeys, err := s.vault.ListSecrets(project)
	if err != nil {
		return dotenv.ImportPlan{}, fmt.Errorf("list existing secrets: %w", err)
	}

	existingSet := make(map[string]bool, len(existingKeys))
	for _, key := range existingKeys {
		existingSet[key] = true
	}

	plan, err := dotenv.PlanImport(files, existingSet, overwrite)
	if err != nil {
		return dotenv.ImportPlan{}, fmt.Errorf("plan dotenv import: %w", err)
	}

	return plan, nil
}

func resolveEnvImportFiles(explicitFiles []string, directory, environment string) ([]string, error) {
	directory = defaultImportDirectory(directory)

	if len(explicitFiles) > 0 {
		baseDir, err := filepath.Abs(directory)
		if err != nil {
			return nil, fmt.Errorf("resolve directory %s: %w", directory, err)
		}

		files := make([]string, 0, len(explicitFiles))
		seen := make(map[string]bool, len(explicitFiles))
		for _, file := range explicitFiles {
			resolved, err := resolveExplicitEnvFile(baseDir, file)
			if err != nil {
				return nil, err
			}
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			files = append(files, resolved)
		}
		if len(files) == 0 {
			return nil, dotenv.ErrNoFilesSelected
		}
		return files, nil
	}

	files, err := dotenv.Discover(directory)
	if err != nil {
		return nil, fmt.Errorf("discover dotenv files: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no safe dotenv files found in %s", directory)
	}

	selection := dotenv.DefaultSelection(files, environment)
	if len(selection) == 0 {
		return nil, fmt.Errorf("no default dotenv files found in %s; provide files explicitly or set an environment", directory)
	}

	return importEnvPaths(selection), nil
}

func importEnvPaths(files []dotenv.DiscoveredFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}

func defaultImportDirectory(directory string) string {
	if strings.TrimSpace(directory) == "" {
		return "."
	}
	return directory
}

func resolveExplicitEnvFile(baseDir, file string) (string, error) {
	resolved := filepath.Clean(file)
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, resolved)
	}

	resolvedAbs, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve dotenv file %s: %w", file, err)
	}

	rel, err := filepath.Rel(baseDir, resolvedAbs)
	if err != nil {
		return "", fmt.Errorf("check dotenv file %s: %w", file, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("dotenv file %s must be inside %s", file, baseDir)
	}

	return resolvedAbs, nil
}
