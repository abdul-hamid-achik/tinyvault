package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
)

var (
	importPromptInput  = bufio.NewReader(os.Stdin)
	importPromptOutput = io.Writer(os.Stderr)
	importPromptIsTTY  = func() bool {
		return term.IsTerminal(int(os.Stdin.Fd()))
	}
)

type importCandidate struct {
	DiagnosticCount int
	KeyCount        int
	Path            string
}

func inspectImportCandidates(files []dotenv.DiscoveredFile) []importCandidate {
	candidates := make([]importCandidate, 0, len(files))
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

		candidates = append(candidates, importCandidate{
			DiagnosticCount: diagnosticCount,
			KeyCount:        keyCount,
			Path:            file.Path,
		})
	}

	return candidates
}

func promptImportFileSelection(candidates []importCandidate, recommended []string) ([]string, error) {
	candidates = orderImportCandidates(candidates, recommended)

	defaultSelection := append([]string(nil), recommended...)
	if len(defaultSelection) == 0 {
		for _, candidate := range candidates {
			defaultSelection = append(defaultSelection, candidate.Path)
		}
	}

	defaultIndices := make([]string, 0, len(defaultSelection))
	defaultSet := make(map[string]bool, len(defaultSelection))
	for _, path := range defaultSelection {
		defaultSet[path] = true
	}

	fmt.Fprintln(importPromptOutput, "Discovered dotenv files:")
	for index, candidate := range candidates {
		marker := ""
		if defaultSet[candidate.Path] {
			marker = " (recommended)"
			defaultIndices = append(defaultIndices, strconv.Itoa(index+1))
		}

		details := fmt.Sprintf("%d key(s)", candidate.KeyCount)
		if candidate.DiagnosticCount > 0 {
			details += fmt.Sprintf(", %d issue(s)", candidate.DiagnosticCount)
		}

		fmt.Fprintf(importPromptOutput, "  %d. %s - %s%s\n", index+1, candidate.Path, details, marker)
	}
	fmt.Fprintln(importPromptOutput, "Later files override earlier ones during import planning.")
	if len(defaultIndices) > 0 {
		fmt.Fprintf(importPromptOutput, "Select files to import [default: %s]: ", strings.Join(defaultIndices, ","))
	} else {
		fmt.Fprint(importPromptOutput, "Select files to import (comma separated indices): ")
	}

	line, err := readImportPromptLine()
	if err != nil {
		return nil, err
	}
	if line == "" {
		return defaultSelection, nil
	}

	parts := strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 {
		return nil, dotenv.ErrNoFilesSelected
	}

	selection := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		index, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid selection %q", part)
		}
		if index < 1 || index > len(candidates) {
			return nil, fmt.Errorf("selection %d is out of range", index)
		}

		path := candidates[index-1].Path
		if seen[path] {
			continue
		}
		seen[path] = true
		selection = append(selection, path)
	}

	return selection, nil
}

func orderImportCandidates(candidates []importCandidate, recommended []string) []importCandidate {
	ordered := append([]importCandidate(nil), candidates...)
	if len(recommended) == 0 {
		return ordered
	}

	recommendedOrder := make(map[string]int, len(recommended))
	for index, path := range recommended {
		recommendedOrder[path] = index
	}

	sort.SliceStable(ordered, func(i, j int) bool {
		leftIndex, leftRecommended := recommendedOrder[ordered[i].Path]
		rightIndex, rightRecommended := recommendedOrder[ordered[j].Path]

		switch {
		case leftRecommended && rightRecommended:
			return leftIndex < rightIndex
		case leftRecommended:
			return true
		case rightRecommended:
			return false
		default:
			return ordered[i].Path < ordered[j].Path
		}
	})

	return ordered
}

func promptImportConfirmation() (bool, error) {
	fmt.Fprint(importPromptOutput, "Import these dotenv secrets? [y/N]: ")
	line, err := readImportPromptLine()
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes", nil
}

func readImportPromptLine() (string, error) {
	line, err := importPromptInput.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
