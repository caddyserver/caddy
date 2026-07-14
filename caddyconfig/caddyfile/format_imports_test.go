// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverImportedFiles(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	writeFile(t, root, "import sites/*.caddy\nimport mysnip\n")
	os.MkdirAll(filepath.Join(dir, "sites"), 0o755)
	writeFile(t, filepath.Join(dir, "sites", "a.caddy"), "(mysnip) {\n\trespond 200\n}\nlocalhost {\n\timport mysnip\n}\n")
	rootInput, _ := os.ReadFile(root)
	files, err := discoverImportedFiles(root, rootInput)
	if err != nil {
		t.Fatal(err)
	}
	// sites/a.caddy is discovered; "mysnip" is a snippet (defined in a.caddy), not a file
	want := []string{filepath.Join(dir, "sites", "a.caddy")}
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }
	if len(files) != 1 || abs(files[0]) != abs(want[0]) {
		t.Errorf("got %v, want %v", files, want)
	}
}

func TestFormatImports(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	writeFile(t, root, "import sites/a.caddy\n")
	os.MkdirAll(filepath.Join(dir, "sites"), 0o755)
	// deliberately messy imported file to prove it gets formatted at baseline 0
	writeFile(t, filepath.Join(dir, "sites", "a.caddy"), "localhost{\nrespond   200\n}\n")
	results, err := FormatImports(root, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	// results[0] is the root; results[1] is the imported file, formatted
	var imported *FormattedFile
	for i := range results {
		if strings.HasSuffix(results[i].Path, "a.caddy") {
			imported = &results[i]
		}
	}
	if imported == nil {
		t.Fatal("imported file not in results")
	}
	want := "localhost {\n\trespond 200\n}\n"
	if string(imported.Content) != want {
		t.Errorf("imported formatted = %q, want %q", imported.Content, want)
	}
}

func TestDiscoverIgnoresNonDirectiveImport(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	writeFile(t, root, "localhost {\n\tbasic_auth / import password\n}\n")
	rootInput, _ := os.ReadFile(root)
	files, err := discoverImportedFiles(root, rootInput)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("got %v, want none ('import' here is an argument)", files)
	}
}
