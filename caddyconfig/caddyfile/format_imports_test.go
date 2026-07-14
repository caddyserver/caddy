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
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func discoverImportedFiles(rootFile string, rootInput []byte) ([]string, error) {
	rootPath, err := canonicalPath(rootFile)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Stat(rootPath)
	if err != nil {
		return nil, err
	}
	files, err := discoverImportedFileContents(rootFile, rootInput, rootInfo)
	if err != nil {
		return nil, err
	}
	paths := make([]string, len(files))
	for i, file := range files {
		paths[i] = file.path
	}
	return paths, nil
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
	writeFile(t, filepath.Join(dir, "sites", "a.caddy"), "localhost {\nrespond   200\n}\n")
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

func TestDiscoverImportBeforeSnippetDeclarationIsFile(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	writeFile(t, root, "import foo\n\n(foo) {\n\trespond ok\n}\n")
	writeFile(t, filepath.Join(dir, "foo"), "localhost {\n\trespond from-file\n}\n")

	rootInput, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := discoverImportedFiles(root, rootInput)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != mustCanonicalPath(t, filepath.Join(dir, "foo")) {
		t.Fatalf("got %v, want foo file", files)
	}
}

func TestDiscoverRecursiveImportArgs(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	selector := filepath.Join(dir, "selector.caddy")
	child := filepath.Join(dir, "child.caddy")
	writeFile(t, root, "import selector.caddy child.caddy\n")
	writeFile(t, selector, "import {args[0]}\n")
	writeFile(t, child, "localhost {\n\trespond ok\n}\n")

	results, err := FormatImports(root, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{mustCanonicalPath(t, root), mustCanonicalPath(t, selector), mustCanonicalPath(t, child)}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d: %v", len(results), len(want), results)
	}
	for i := range want {
		if results[i].Path != want[i] {
			t.Errorf("result %d path = %q, want %q", i, results[i].Path, want[i])
		}
	}
}

func TestDiscoverDeduplicatesSymlinksAndCycles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available on Windows")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	child := filepath.Join(dir, "child.caddy")
	writeFile(t, root, "import child.caddy\nimport child-link.caddy\nimport dir-link/Caddyfile\n")
	writeFile(t, child, "localhost {\n\trespond ok\n}\n")
	if err := os.Symlink(child, filepath.Join(dir, "child-link.caddy")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(dir, "dir-link")); err != nil {
		t.Fatal(err)
	}

	results, err := FormatImports(root, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got paths %v, want root and one physical child", resultPaths(results))
	}
	if results[1].Path != mustCanonicalPath(t, child) {
		t.Fatalf("imported path = %q, want %q", results[1].Path, child)
	}
}

func TestDiscoverExpandsEnvironmentBeforeLexing(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	child := filepath.Join(dir, "child # file.caddy")
	t.Setenv("CADDYFILE_IMPORT_LINE", `"import" "child # file.caddy" # generated comment`)
	writeFile(t, root, "{$CADDYFILE_IMPORT_LINE}\n")
	writeFile(t, child, "localhost {\n\trespond ok\n}\n")

	results, err := FormatImports(root, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[1].Path != mustCanonicalPath(t, child) {
		t.Fatalf("got paths %v, want generated quoted import %q", resultPaths(results), child)
	}
}

func TestDiscoverIgnoresImportsInUnusedSnippetAndImportBlock(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	template := filepath.Join(dir, "template.caddy")
	dead := filepath.Join(dir, "dead.caddy")
	writeFile(t, root, `(unused) {
	import dead.caddy
}

import template.caddy {
	unused {
		import dead.caddy
	}
}
`)
	writeFile(t, template, "localhost {\n\trespond ok\n}\n")
	writeFile(t, dead, "dead.example {\n\trespond dead\n}\n")

	results, err := FormatImports(root, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[1].Path != mustCanonicalPath(t, template) {
		t.Fatalf("got paths %v, want only active template import", resultPaths(results))
	}
}

func TestDiscoverQuotedImportDirective(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	child := filepath.Join(dir, "child.caddy")
	writeFile(t, root, `"import" child.caddy`+"\n")
	writeFile(t, child, "localhost {\n\trespond ok\n}\n")

	results, err := FormatImports(root, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[1].Path != mustCanonicalPath(t, child) {
		t.Fatalf("got paths %v, want quoted import", resultPaths(results))
	}
}

func TestDiscoverUnreadableImportReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission mode test")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	child := filepath.Join(dir, "child.caddy")
	writeFile(t, root, "import child.caddy\n")
	writeFile(t, child, "localhost\n")
	if err := os.Chmod(child, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(child, 0o600) })
	if file, err := os.Open(child); err == nil {
		file.Close()
		t.Skip("test process can read mode-000 files")
	}

	if _, err := FormatImports(root, FormatOptions{}); err == nil {
		t.Fatal("expected unreadable matched import to return an error")
	}
}

func TestFormatImportsNormalizesAllPaths(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	linkDir := filepath.Join(dir, "link")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(realDir, "Caddyfile")
	rootLink := filepath.Join(linkDir, "Caddyfile")
	child := filepath.Join(linkDir, "child.caddy")
	writeFile(t, realRoot, "import child.caddy\n")
	writeFile(t, child, "localhost {\n\trespond ok\n}\n")
	if err := os.Symlink(realRoot, rootLink); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symlink: %v", err)
		}
		t.Fatal(err)
	}

	results, err := FormatImports(rootLink, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{mustCanonicalPath(t, realRoot), mustCanonicalPath(t, child)}
	if got := resultPaths(results); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got paths %v, want canonical paths %v", got, want)
	}
}

func TestDiscoveryRetainsImportedContent(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	child := filepath.Join(dir, "child.caddy")
	writeFile(t, root, "import child.caddy\n")
	writeFile(t, child, "localhost {\nrespond   old\n}\n")
	rootInput, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}

	files, err := discoverImportedFileContents(root, rootInput, rootInfo)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, child, "localhost {\n\trespond replacement\n}\n")
	if len(files) != 1 || string(files[0].content) != "localhost {\nrespond   old\n}\n" {
		t.Fatalf("discovery did not retain the bytes read by the parser: %+v", files)
	}
}

func resultPaths(results []FormattedFile) []string {
	paths := make([]string, len(results))
	for i := range results {
		paths[i] = results[i].Path
	}
	return paths
}

func mustCanonicalPath(t *testing.T, path string) string {
	t.Helper()
	canonical, err := canonicalPath(path)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
