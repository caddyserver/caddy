package templates

import (
	"testing"
)

func TestExtractFrontMatterYAML(t *testing.T) {
	input := "---\ntitle: Hello\nauthor: World\n---\nBody content here"
	fm, body, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm["title"] != "Hello" {
		t.Errorf("title = %v, want 'Hello'", fm["title"])
	}
	if fm["author"] != "World" {
		t.Errorf("author = %v, want 'World'", fm["author"])
	}
	if body != "\nBody content here" {
		t.Errorf("body = %q, want %q", body, "\nBody content here")
	}
}

func TestExtractFrontMatterYAMLDotsClosing(t *testing.T) {
	input := "---\ntitle: Test\n...\nBody after dots"
	fm, body, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm["title"] != "Test" {
		t.Errorf("title = %v, want 'Test'", fm["title"])
	}
	if body != "\nBody after dots" {
		t.Errorf("body = %q, want %q", body, "\nBody after dots")
	}
}

func TestExtractFrontMatterTOML(t *testing.T) {
	input := "+++\ntitle = \"TOML Test\"\ncount = 42\n+++\nBody here"
	fm, body, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm["title"] != "TOML Test" {
		t.Errorf("title = %v, want 'TOML Test'", fm["title"])
	}
	if fm["count"] != int64(42) {
		t.Errorf("count = %v (%T), want 42", fm["count"], fm["count"])
	}
	if body != "\nBody here" {
		t.Errorf("body = %q, want %q", body, "\nBody here")
	}
}

func TestExtractFrontMatterJSON(t *testing.T) {
	// JSON front matter uses { as open and } as close
	// The parser wraps content with {} so the actual content should not include outer braces
	input := "{\n\"title\": \"JSON Test\"\n}\nBody here"
	fm, body, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm["title"] != "JSON Test" {
		t.Errorf("title = %v, want 'JSON Test'", fm["title"])
	}
	if body != "\nBody here" {
		t.Errorf("body = %q, want %q", body, "\nBody here")
	}
}

func TestExtractFrontMatterNone(t *testing.T) {
	input := "Just regular content\nNo front matter here"
	fm, body, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm != nil {
		t.Errorf("expected nil front matter, got %v", fm)
	}
	if body != input {
		t.Errorf("body should equal input when no front matter")
	}
}

func TestExtractFrontMatterEmpty(t *testing.T) {
	fm, body, err := extractFrontMatter("")
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm != nil {
		t.Errorf("expected nil front matter for empty input, got %v", fm)
	}
	if body != "" {
		t.Errorf("body = %q, want empty string", body)
	}
}

func TestExtractFrontMatterUnterminated(t *testing.T) {
	input := "---\ntitle: Hello\nNo closing fence"
	_, _, err := extractFrontMatter(input)
	if err == nil {
		t.Error("expected error for unterminated front matter")
	}
}

func TestExtractFrontMatterFrontMatterOnly(t *testing.T) {
	input := "---\ntitle: Only\n---"
	fm, body, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm["title"] != "Only" {
		t.Errorf("title = %v, want 'Only'", fm["title"])
	}
	if body != "" {
		t.Errorf("body = %q, want empty string", body)
	}
}

func TestExtractFrontMatterLeadingBlankLines(t *testing.T) {
	input := "\n\n---\ntitle: Indented\n---\nBody"
	fm, body, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm["title"] != "Indented" {
		t.Errorf("title = %v, want 'Indented'", fm["title"])
	}
	if body != "\nBody" {
		t.Errorf("body = %q, want %q", body, "\nBody")
	}
}

func TestExtractFrontMatterWindowsCRLF(t *testing.T) {
	input := "---\r\ntitle: CRLF\r\n---\r\nBody"
	fm, body, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm["title"] != "CRLF" {
		t.Errorf("title = %v, want 'CRLF'", fm["title"])
	}
	if body == "" {
		t.Error("body should not be empty")
	}
}

func TestExtractFrontMatterInvalidYAML(t *testing.T) {
	input := "---\n: invalid: yaml: [broken\n---\nBody"
	_, _, err := extractFrontMatter(input)
	if err == nil {
		t.Error("expected error for invalid YAML front matter")
	}
}

func TestExtractFrontMatterMultipleYAMLFields(t *testing.T) {
	input := "---\ntitle: Multi\ndate: 2024-01-01\ntags:\n  - go\n  - caddy\n---\nBody"
	fm, _, err := extractFrontMatter(input)
	if err != nil {
		t.Fatalf("extractFrontMatter() error: %v", err)
	}
	if fm["title"] != "Multi" {
		t.Errorf("title = %v, want 'Multi'", fm["title"])
	}
	if fm["date"] == nil {
		t.Error("date should not be nil")
	}
	tags, ok := fm["tags"].([]any)
	if !ok {
		t.Fatalf("tags is %T, want []any", fm["tags"])
	}
	if len(tags) != 2 {
		t.Errorf("len(tags) = %d, want 2", len(tags))
	}
}

func TestYamlFrontMatter(t *testing.T) {
	m, err := yamlFrontMatter([]byte("\ntitle: test\n"))
	if err != nil {
		t.Fatalf("yamlFrontMatter() error: %v", err)
	}
	if m["title"] != "test" {
		t.Errorf("title = %v, want 'test'", m["title"])
	}
}

func TestTomlFrontMatter(t *testing.T) {
	m, err := tomlFrontMatter([]byte("\ntitle = \"test\"\n"))
	if err != nil {
		t.Fatalf("tomlFrontMatter() error: %v", err)
	}
	if m["title"] != "test" {
		t.Errorf("title = %v, want 'test'", m["title"])
	}
}

func TestJsonFrontMatter(t *testing.T) {
	// jsonFrontMatter wraps input with { } before parsing
	m, err := jsonFrontMatter([]byte("\n\"title\": \"test\"\n"))
	if err != nil {
		t.Fatalf("jsonFrontMatter() error: %v", err)
	}
	if m["title"] != "test" {
		t.Errorf("title = %v, want 'test'", m["title"])
	}
}
