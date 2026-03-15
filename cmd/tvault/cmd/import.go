package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var (
	importDirectory   string
	importEnvironment string
	importFiles       []string
	importOverwrite   bool
	importDryRun      bool
	importInteractive bool
)

var importCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import secrets from dotenv files",
	Long: `Import secrets from one or more dotenv files into the current project.

Supports explicit files like .env, .env.local, and .env.production, or safe
dotenv-family discovery with --env and --interactive. Files are merged in order
and later files override earlier ones during planning.

Examples:
  tvault import .env
  tvault import --env production
  tvault import --interactive --env production
  tvault import --file .env --file .env.local --overwrite
  tvault import --dir ./config --dry-run`,
	Args: cobra.MaximumNArgs(1),
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(importCmd)
	importCmd.Flags().StringVar(&importDirectory, "dir", ".", "Directory to scan for dotenv files")
	importCmd.Flags().StringVar(&importEnvironment, "env", "", "Environment name for default dotenv chain (for example production)")
	importCmd.Flags().StringArrayVar(&importFiles, "file", nil, "Dotenv file to import in order (can be repeated)")
	importCmd.Flags().BoolVar(&importOverwrite, "overwrite", false, "Overwrite existing secrets")
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Show what would be imported without making changes")
	importCmd.Flags().BoolVar(&importInteractive, "interactive", false, "Interactively select and preview dotenv files before importing")
}

func runImport(_ *cobra.Command, args []string) error {
	selectedFiles, err := resolveImportPaths(args)
	if err != nil {
		return err
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)

	plan, err := buildImportPlan(v, project, selectedFiles)
	if err != nil {
		return err
	}

	printImportDiagnostics(plan.Diagnostics)
	if len(plan.Entries) == 0 {
		Warning("No valid secrets found in the selected dotenv files")
		return nil
	}

	if importDryRun || importInteractive {
		printImportEntries(plan, true)
		printImportSummary(plan, true)
	}

	if importDryRun {
		return nil
	}

	if importInteractive {
		confirmed, confirmErr := promptImportConfirmation()
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			Info("Canceled")
			return nil
		}
	}

	result, err := applyImportPlan(v, project, plan)
	if err != nil {
		return err
	}

	if !importInteractive {
		printImportEntries(plan, false)
	}
	printAppliedImportSummary(result)

	return nil
}

func resolveImportPaths(args []string) ([]string, error) {
	if len(args) == 1 && len(importFiles) > 0 {
		return nil, fmt.Errorf("cannot combine an explicit file argument with --file")
	}

	if importInteractive && !importPromptIsTTY() {
		return nil, fmt.Errorf("--interactive requires a terminal; use --file or an explicit file path instead")
	}

	if len(args) == 1 {
		return []string{filepath.Clean(args[0])}, nil
	}

	if len(importFiles) > 0 {
		files := make([]string, 0, len(importFiles))
		seen := make(map[string]bool, len(importFiles))
		for _, file := range importFiles {
			clean := filepath.Clean(file)
			if seen[clean] {
				continue
			}
			seen[clean] = true
			files = append(files, clean)
		}
		return files, nil
	}

	discovered, err := dotenv.Discover(importDirectory)
	if err != nil {
		return nil, fmt.Errorf("failed to discover dotenv files: %w", err)
	}
	if len(discovered) == 0 {
		return nil, fmt.Errorf("no safe dotenv files found in %s", importDirectory)
	}

	defaultSelection := dotenv.DefaultSelection(discovered, importEnvironment)
	if importInteractive {
		candidates := inspectImportCandidates(discovered)

		recommended := discoveredPaths(defaultSelection)
		if len(recommended) == 0 {
			recommended = discoveredPaths(discovered)
		}

		selected, err := promptImportFileSelection(candidates, recommended)
		if err != nil {
			return nil, err
		}
		if len(selected) == 0 {
			return nil, dotenv.ErrNoFilesSelected
		}
		return selected, nil
	}

	if len(defaultSelection) == 0 {
		return nil, fmt.Errorf("no default dotenv files found in %s; use --env, --file, or --interactive", importDirectory)
	}

	return discoveredPaths(defaultSelection), nil
}

func buildImportPlan(v *vault.Vault, project string, files []string) (dotenv.ImportPlan, error) {
	existingKeys, err := v.ListSecrets(project)
	if err != nil {
		return dotenv.ImportPlan{}, fmt.Errorf("failed to list existing secrets: %w", err)
	}

	existingSet := make(map[string]bool, len(existingKeys))
	for _, key := range existingKeys {
		existingSet[key] = true
	}

	plan, err := dotenv.PlanImport(files, existingSet, importOverwrite)
	if err != nil {
		return dotenv.ImportPlan{}, fmt.Errorf("failed to plan dotenv import: %w", err)
	}

	return plan, nil
}

type importApplyResult struct {
	ImportedCount    int
	OverwriteCount   int
	SkippedCount     int
	SelectedFileList []string
}

func applyImportPlan(v *vault.Vault, project string, plan dotenv.ImportPlan) (importApplyResult, error) {
	result := importApplyResult{
		SelectedFileList: append([]string(nil), plan.Files...),
	}

	for _, entry := range plan.Entries {
		switch entry.Action {
		case dotenv.ActionSkip:
			result.SkippedCount++
			continue
		case dotenv.ActionCreate, dotenv.ActionOverwrite:
			if err := v.SetSecret(project, entry.Key, entry.Value); err != nil {
				return result, fmt.Errorf("failed to set %s: %w", entry.Key, err)
			}
			if entry.Action == dotenv.ActionCreate {
				result.ImportedCount++
			} else {
				result.OverwriteCount++
			}
		default:
			return result, fmt.Errorf("unsupported import action %q", entry.Action)
		}
	}

	return result, nil
}

func printImportDiagnostics(diagnostics []dotenv.Diagnostic) {
	if len(diagnostics) == 0 {
		return
	}

	Warning("Skipped %d unsupported or invalid dotenv line(s)", len(diagnostics))
	for _, diagnostic := range diagnostics {
		if diagnostic.Line > 0 {
			fmt.Printf("  %s %s:%d %s\n", WarningIcon(), diagnostic.Path, diagnostic.Line, diagnostic.Message)
			continue
		}
		fmt.Printf("  %s %s %s\n", WarningIcon(), diagnostic.Path, diagnostic.Message)
	}
	fmt.Println()
}

func printImportEntries(plan dotenv.ImportPlan, preview bool) {
	for _, entry := range plan.Entries {
		if preview {
			switch entry.Action {
			case dotenv.ActionCreate:
				fmt.Printf("  %s %s (would create from %s)\n", SuccessIcon(), entry.Key, entry.SourcePath)
			case dotenv.ActionOverwrite:
				fmt.Printf("  %s %s (would overwrite from %s)\n", SuccessIcon(), entry.Key, entry.SourcePath)
			case dotenv.ActionSkip:
				fmt.Printf("  %s %s (would skip - already exists, source %s)\n", WarningIcon(), entry.Key, entry.SourcePath)
			}
			continue
		}

		switch entry.Action {
		case dotenv.ActionCreate:
			fmt.Printf("  %s %s (created from %s)\n", SuccessIcon(), entry.Key, entry.SourcePath)
		case dotenv.ActionOverwrite:
			fmt.Printf("  %s %s (overwritten from %s)\n", SuccessIcon(), entry.Key, entry.SourcePath)
		case dotenv.ActionSkip:
			fmt.Printf("  %s %s (skipped - already exists, source %s)\n", WarningIcon(), entry.Key, entry.SourcePath)
		}
	}

	if len(plan.Entries) > 0 {
		fmt.Println()
	}
}

func printImportSummary(plan dotenv.ImportPlan, preview bool) {
	actionWord := "Would import"
	if !preview {
		actionWord = "Imported"
	}

	Info("%s %d secret(s) from %d file(s)", actionWord, plan.CreateCount+plan.OverwriteCount, len(plan.Files))
	if plan.SkipCount > 0 {
		Info("Would skip %d existing secret(s)%s", plan.SkipCount, overwriteHint(preview))
	}
}

func printAppliedImportSummary(result importApplyResult) {
	if result.ImportedCount > 0 || result.OverwriteCount > 0 {
		Success("Imported %d secret(s) from %d file(s)", result.ImportedCount+result.OverwriteCount, len(result.SelectedFileList))
	}
	if result.OverwriteCount > 0 {
		Info("Overwrote %d existing secret(s)", result.OverwriteCount)
	}
	if result.SkippedCount > 0 {
		Info("Skipped %d existing secret(s). Use --overwrite to replace them.", result.SkippedCount)
	}
}

func overwriteHint(preview bool) string {
	if preview {
		return ". Use --overwrite to replace them."
	}
	return ""
}

func discoveredPaths(files []dotenv.DiscoveredFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}
