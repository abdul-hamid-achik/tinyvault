package dotenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscover(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{
		".env",
		".env.local",
		".env.production",
		".env.production.local",
		".env.example",
		".env.sample",
		".env.dist",
		".env.production.backup",
		".envrc",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("KEY=value\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	files, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	got := make([]string, 0, len(files))
	for _, file := range files {
		got = append(got, file.Name)
	}

	want := []string{".env", ".env.local", ".env.production", ".env.production.local"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("discovered files = %v, want %v", got, want)
	}
}

func TestDiscoverSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".env")
	link := filepath.Join(dir, ".env.local")

	if err := os.WriteFile(target, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	files, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(files) != 1 || files[0].Name != ".env" {
		t.Fatalf("discover result = %+v, want only .env", files)
	}
}

func TestDefaultSelection(t *testing.T) {
	files := []DiscoveredFile{
		{Name: ".env", Path: ".env"},
		{Name: ".env.local", Path: ".env.local"},
		{Name: ".env.production", Path: ".env.production"},
		{Name: ".env.production.local", Path: ".env.production.local"},
	}

	t.Run("default", func(t *testing.T) {
		selection := DefaultSelection(files, "")
		if len(selection) != 2 {
			t.Fatalf("selection length = %d, want 2", len(selection))
		}
		if selection[0].Name != ".env" || selection[1].Name != ".env.local" {
			t.Fatalf("unexpected default selection: %+v", selection)
		}
	})

	t.Run("production", func(t *testing.T) {
		selection := DefaultSelection(files, "production")
		got := []string{selection[0].Name, selection[1].Name, selection[2].Name, selection[3].Name}
		want := []string{".env", ".env.production", ".env.local", ".env.production.local"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("selection = %v, want %v", got, want)
		}
	})
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := strings.Join([]string{
		"# comment",
		"export API_KEY=abc123",
		"EMPTY=",
		"QUOTED=\"line1\\nline2\"",
		"SINGLE='literal\\nvalue'",
		"SPACE = value with spaces",
		"INVALID-KEY=nope",
		"BROKEN_LINE",
		"DUP=first",
		"DUP=second",
		"UNTERMINATED=\"oops",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if len(parsed.Entries) != 6 {
		t.Fatalf("entry count = %d, want 6", len(parsed.Entries))
	}

	entries := make(map[string]ParsedEntry, len(parsed.Entries))
	for _, entry := range parsed.Entries {
		entries[entry.Key] = entry
	}

	if entries["API_KEY"].Value != "abc123" {
		t.Fatalf("API_KEY = %q, want %q", entries["API_KEY"].Value, "abc123")
	}
	if entries["EMPTY"].Value != "" {
		t.Fatalf("EMPTY = %q, want empty string", entries["EMPTY"].Value)
	}
	if entries["QUOTED"].Value != "line1\nline2" {
		t.Fatalf("QUOTED = %q, want newline-expanded value", entries["QUOTED"].Value)
	}
	if entries["SINGLE"].Value != "literal\\nvalue" {
		t.Fatalf("SINGLE = %q, want literal backslash-n", entries["SINGLE"].Value)
	}
	if entries["DUP"].Value != "second" {
		t.Fatalf("DUP = %q, want %q", entries["DUP"].Value, "second")
	}

	if len(parsed.Diagnostics) != 4 {
		t.Fatalf("diagnostic count = %d, want 4", len(parsed.Diagnostics))
	}
}

func TestParseFileInlineComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := strings.Join([]string{
		"PLAIN=value # comment",
		"DOUBLE=\"quoted value\" # trailing comment",
		"SINGLE='quoted literal' # trailing comment",
		"HASHED=value#not-comment",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	entries := make(map[string]ParsedEntry, len(parsed.Entries))
	for _, entry := range parsed.Entries {
		entries[entry.Key] = entry
	}

	if entries["PLAIN"].Value != "value" {
		t.Fatalf("PLAIN = %q, want %q", entries["PLAIN"].Value, "value")
	}
	if entries["DOUBLE"].Value != "quoted value" {
		t.Fatalf("DOUBLE = %q, want %q", entries["DOUBLE"].Value, "quoted value")
	}
	if entries["SINGLE"].Value != "quoted literal" {
		t.Fatalf("SINGLE = %q, want %q", entries["SINGLE"].Value, "quoted literal")
	}
	if entries["HASHED"].Value != "value#not-comment" {
		t.Fatalf("HASHED = %q, want %q", entries["HASHED"].Value, "value#not-comment")
	}
}

func TestParseFileRejectsUnsafeExplicitPaths(t *testing.T) {
	dir := t.TempDir()
	unsafe := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(unsafe, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatalf("write unsafe file: %v", err)
	}

	if _, err := ParseFile(unsafe); err == nil {
		t.Fatal("expected unsupported dotenv filename to be rejected")
	}
}

func TestParseFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".env")
	link := filepath.Join(dir, ".env.local")
	if err := os.WriteFile(target, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	if _, err := ParseFile(link); err == nil {
		t.Fatal("expected symlink dotenv file to be rejected")
	}
}

func TestParseFileLongLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	value := strings.Repeat("x", 128*1024)
	if err := os.WriteFile(path, []byte("LONG="+value+"\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(parsed.Entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(parsed.Entries))
	}
	if parsed.Entries[0].Value != value {
		t.Fatal("long line value did not round-trip")
	}
}

func TestPlanImport(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, ".env")
	localPath := filepath.Join(dir, ".env.local")

	if err := os.WriteFile(basePath, []byte("API_KEY=base\nNEW_KEY=fresh\n"), 0o600); err != nil {
		t.Fatalf("write base file: %v", err)
	}
	if err := os.WriteFile(localPath, []byte("API_KEY=local\nLOCAL_ONLY=1\n"), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	plan, err := PlanImport([]string{basePath, localPath}, map[string]bool{"API_KEY": true}, false)
	if err != nil {
		t.Fatalf("PlanImport: %v", err)
	}

	if plan.CreateCount != 2 {
		t.Fatalf("CreateCount = %d, want 2", plan.CreateCount)
	}
	if plan.SkipCount != 1 {
		t.Fatalf("SkipCount = %d, want 1", plan.SkipCount)
	}
	if plan.OverwriteCount != 0 {
		t.Fatalf("OverwriteCount = %d, want 0", plan.OverwriteCount)
	}

	entries := make(map[string]PlannedEntry, len(plan.Entries))
	for _, entry := range plan.Entries {
		entries[entry.Key] = entry
	}

	if entries["API_KEY"].Action != ActionSkip {
		t.Fatalf("API_KEY action = %q, want %q", entries["API_KEY"].Action, ActionSkip)
	}
	if entries["API_KEY"].Value != "local" {
		t.Fatalf("API_KEY value = %q, want %q", entries["API_KEY"].Value, "local")
	}
	if entries["NEW_KEY"].Action != ActionCreate {
		t.Fatalf("NEW_KEY action = %q, want %q", entries["NEW_KEY"].Action, ActionCreate)
	}
	if entries["LOCAL_ONLY"].Action != ActionCreate {
		t.Fatalf("LOCAL_ONLY action = %q, want %q", entries["LOCAL_ONLY"].Action, ActionCreate)
	}
}

func TestPlanImportNoFilesSelected(t *testing.T) {
	_, err := PlanImport(nil, nil, false)
	if !errors.Is(err, ErrNoFilesSelected) {
		t.Fatalf("expected ErrNoFilesSelected, got %v", err)
	}
}
