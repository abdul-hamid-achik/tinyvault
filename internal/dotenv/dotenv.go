package dotenv

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/abdul-hamid-achik/tinyvault/internal/validation"
)

const maxFileSizeBytes int64 = 1 << 20

var (
	// ErrNoFilesSelected is returned when an import plan is requested without files.
	ErrNoFilesSelected = errors.New("no dotenv files selected")
	// ErrNoFilesFound is returned when discovery finds no safe dotenv files.
	ErrNoFilesFound = errors.New("no dotenv files found")
)

var ignoredEnvironmentNames = map[string]struct{}{
	"dist":     {},
	"example":  {},
	"sample":   {},
	"template": {},
}

// DiscoveredFile describes a safe dotenv file found on disk.
type DiscoveredFile struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Diagnostic reports a safe parser or planning issue without including values.
type Diagnostic struct {
	Path    string `json:"path"`
	Line    int    `json:"line,omitempty"`
	Key     string `json:"key,omitempty"`
	Message string `json:"message"`
}

// ParsedEntry is a parsed dotenv key/value pair.
type ParsedEntry struct {
	Key   string
	Line  int
	Path  string
	Value string
}

// ParsedFile is the parsed representation of a dotenv file.
type ParsedFile struct {
	Diagnostics []Diagnostic
	Entries     []ParsedEntry
	Name        string
	Path        string
}

// ImportAction describes what an import would do for a key.
type ImportAction string

const (
	// ActionCreate creates a new key in the vault.
	ActionCreate ImportAction = "create"
	// ActionOverwrite updates an existing key in the vault.
	ActionOverwrite ImportAction = "overwrite"
	// ActionSkip leaves an existing key unchanged.
	ActionSkip ImportAction = "skip"
)

// PlannedEntry describes the final merged value for a key and the action to take.
type PlannedEntry struct {
	Action     ImportAction
	Key        string
	SourceLine int
	SourcePath string
	Value      string
}

// ImportPlan is the merged result of one or more dotenv files.
type ImportPlan struct {
	Diagnostics    []Diagnostic
	Entries        []PlannedEntry
	Files          []string
	ParsedFiles    []ParsedFile
	CreateCount    int
	OverwriteCount int
	SkipCount      int
}

// Discover returns all safe dotenv-family files in a directory.
func Discover(dir string) ([]DiscoveredFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	files := make([]DiscoveredFile, 0, len(entries))
	for _, entry := range entries {
		if !isSafeDotenvName(entry.Name()) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		files = append(files, DiscoveredFile{
			Path: filepath.Join(dir, entry.Name()),
			Name: entry.Name(),
			Size: info.Size(),
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Name < files[j].Name
	})

	return files, nil
}

// DefaultSelection returns the recommended dotenv chain for an environment.
func DefaultSelection(files []DiscoveredFile, environment string) []DiscoveredFile {
	if len(files) == 0 {
		return nil
	}

	byName := make(map[string]DiscoveredFile, len(files))
	for _, file := range files {
		byName[file.Name] = file
	}

	names := []string{".env"}
	if environment != "" {
		names = append(names, ".env."+environment)
	}
	names = append(names, ".env.local")
	if environment != "" {
		names = append(names, ".env."+environment+".local")
	}

	selection := make([]DiscoveredFile, 0, len(names))
	for _, name := range names {
		if file, ok := byName[name]; ok {
			selection = append(selection, file)
		}
	}

	return selection
}

// ParseFile reads a dotenv file without executing shell features.
func ParseFile(path string) (ParsedFile, error) {
	if !isSafeDotenvName(filepath.Base(path)) {
		return ParsedFile{}, fmt.Errorf("%s is not a supported dotenv file name", path)
	}

	file, err := openParseTarget(path)
	if err != nil {
		return ParsedFile{}, err
	}
	defer func() { _ = file.Close() }()

	parsed := ParsedFile{
		Name: filepath.Base(path),
		Path: path,
	}

	entriesByKey, diagnostics, err := parseEntries(path, file)
	if err != nil {
		return ParsedFile{}, err
	}
	parsed.Diagnostics = diagnostics
	parsed.Entries = buildOrderedEntries(entriesByKey)

	return parsed, nil
}

func parseEntries(path string, reader io.Reader) (map[string]ParsedEntry, []Diagnostic, error) {
	buffered := bufio.NewReader(reader)
	entriesByKey := make(map[string]ParsedEntry)
	diagnostics := []Diagnostic{}
	lineNumber := 0

	for {
		line, readErr := buffered.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, nil, readErr
		}
		if errors.Is(readErr, io.EOF) && line == "" {
			break
		}

		lineNumber++
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		entry, diagnostic := parseLine(path, lineNumber, line)
		if diagnostic != nil {
			diagnostics = append(diagnostics, *diagnostic)
		}
		if entry != nil {
			if _, exists := entriesByKey[entry.Key]; exists {
				diagnostics = append(diagnostics, Diagnostic{
					Path:    path,
					Line:    lineNumber,
					Key:     entry.Key,
					Message: "key redefined in file; last value wins",
				})
			}
			entriesByKey[entry.Key] = *entry
		}

		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	return entriesByKey, diagnostics, nil
}

func buildOrderedEntries(entriesByKey map[string]ParsedEntry) []ParsedEntry {
	keys := make([]string, 0, len(entriesByKey))
	for key := range entriesByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	entries := make([]ParsedEntry, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, entriesByKey[key])
	}

	return entries
}

// ParseFiles parses files in order.
func ParseFiles(paths []string) ([]ParsedFile, error) {
	normalized, err := normalizePaths(paths)
	if err != nil {
		return nil, err
	}

	parsed := make([]ParsedFile, 0, len(normalized))
	for _, path := range normalized {
		file, err := ParseFile(path)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, file)
	}

	return parsed, nil
}

// PlanImport merges dotenv files in order and computes import actions.
func PlanImport(paths []string, existingKeys map[string]bool, overwrite bool) (ImportPlan, error) {
	parsedFiles, err := ParseFiles(paths)
	if err != nil {
		return ImportPlan{}, err
	}

	plan := ImportPlan{
		Files:       make([]string, 0, len(parsedFiles)),
		ParsedFiles: parsedFiles,
	}

	merged := make(map[string]ParsedEntry)
	for _, parsedFile := range parsedFiles {
		plan.Files = append(plan.Files, parsedFile.Path)
		plan.Diagnostics = append(plan.Diagnostics, parsedFile.Diagnostics...)
		for _, entry := range parsedFile.Entries {
			merged[entry.Key] = entry
		}
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	plan.Entries = make([]PlannedEntry, 0, len(keys))
	for _, key := range keys {
		entry := merged[key]
		planned := PlannedEntry{
			Key:        key,
			SourceLine: entry.Line,
			SourcePath: entry.Path,
			Value:      entry.Value,
		}

		if existingKeys[key] {
			if overwrite {
				planned.Action = ActionOverwrite
				plan.OverwriteCount++
			} else {
				planned.Action = ActionSkip
				plan.SkipCount++
			}
		} else {
			planned.Action = ActionCreate
			plan.CreateCount++
		}

		plan.Entries = append(plan.Entries, planned)
	}

	return plan, nil
}

func normalizePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, ErrNoFilesSelected
	}

	normalized := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if clean == "." || clean == "" {
			continue
		}
		if seen[clean] {
			continue
		}
		seen[clean] = true
		normalized = append(normalized, clean)
	}

	if len(normalized) == 0 {
		return nil, ErrNoFilesSelected
	}

	return normalized, nil
}

func isSafeDotenvName(name string) bool {
	switch name {
	case ".env", ".env.local":
		return true
	}

	if !strings.HasPrefix(name, ".env.") {
		return false
	}

	suffix := strings.TrimPrefix(name, ".env.")
	parts := strings.Split(suffix, ".")
	if len(parts) == 0 {
		return false
	}

	for _, part := range parts {
		if _, ignored := ignoredEnvironmentNames[part]; ignored {
			return false
		}
	}

	if len(parts) == 1 {
		return parts[0] != ""
	}

	return len(parts) == 2 && parts[0] != "" && parts[1] == "local"
}

func parseLine(path string, lineNumber int, line string) (*ParsedEntry, *Diagnostic) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, nil
	}

	if strings.HasPrefix(trimmed, "export ") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
	}

	separator := strings.Index(trimmed, "=")
	if separator <= 0 {
		return nil, &Diagnostic{
			Path:    path,
			Line:    lineNumber,
			Message: "skipped unsupported line without KEY=VALUE assignment",
		}
	}

	key := strings.TrimSpace(trimmed[:separator])
	valuePart := strings.TrimSpace(trimmed[separator+1:])
	if err := validation.SecretKey(key); err != nil {
		return nil, &Diagnostic{
			Path:    path,
			Line:    lineNumber,
			Key:     key,
			Message: fmt.Sprintf("skipped invalid secret key: %v", err),
		}
	}

	value, ok := parseValue(valuePart)
	if !ok {
		return nil, &Diagnostic{
			Path:    path,
			Line:    lineNumber,
			Key:     key,
			Message: "skipped unterminated quoted value",
		}
	}

	return &ParsedEntry{
		Key:   key,
		Line:  lineNumber,
		Path:  path,
		Value: value,
	}, nil
}

func parseValue(value string) (string, bool) {
	if value == "" {
		return "", true
	}

	if value[0] == '"' {
		content, rest, ok := parseQuotedValue(value, '"', true)
		if !ok {
			return "", false
		}
		return unescapeDoubleQuoted(content), isCommentOrEmpty(rest)
	}

	if value[0] == '\'' {
		content, rest, ok := parseQuotedValue(value, '\'', false)
		if !ok {
			return "", false
		}
		return content, isCommentOrEmpty(rest)
	}

	return trimInlineComment(value), true
}

func parseQuotedValue(value string, quote byte, allowEscapes bool) (string, string, bool) {
	var builder strings.Builder
	escaped := false

	for index := 1; index < len(value); index++ {
		current := value[index]
		if allowEscapes && escaped {
			builder.WriteByte('\\')
			builder.WriteByte(current)
			escaped = false
			continue
		}
		if allowEscapes && current == '\\' {
			escaped = true
			continue
		}
		if current == quote {
			return builder.String(), strings.TrimSpace(value[index+1:]), true
		}
		builder.WriteByte(current)
	}

	return "", "", false
}

func isCommentOrEmpty(value string) bool {
	return value == "" || strings.HasPrefix(value, "#")
}

func trimInlineComment(value string) string {
	for index := 0; index < len(value); index++ {
		if value[index] != '#' {
			continue
		}
		if index == 0 || value[index-1] == ' ' || value[index-1] == '\t' {
			return strings.TrimSpace(value[:index])
		}
	}
	return strings.TrimSpace(value)
}

func unescapeDoubleQuoted(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))

	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index == len(value)-1 {
			builder.WriteByte(value[index])
			continue
		}

		index++
		switch value[index] {
		case 'n':
			builder.WriteByte('\n')
		case 'r':
			builder.WriteByte('\r')
		case 't':
			builder.WriteByte('\t')
		case '"':
			builder.WriteByte('"')
		case '\\':
			builder.WriteByte('\\')
		default:
			builder.WriteByte('\\')
			builder.WriteByte(value[index])
		}
	}

	return builder.String()
}
