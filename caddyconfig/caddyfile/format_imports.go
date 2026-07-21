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
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"
)

type importedFile struct {
	path    string
	content []byte
	info    os.FileInfo
}

// discoverImportedFileContents returns files reached by imports which the parser
// actually executes, in discovery order and excluding rootFile. Driving the real
// parser is important here: import behavior depends on declaration order, snippet
// expansion, import arguments, block substitutions, environment expansion, and
// whether an import appears in active configuration. Reimplementing those rules
// in a separate token scanner caused FormatImports to disagree with adaptation.
//
// The parser calls importObserver after opening and reading each imported file,
// but before inserting its tokens. The observer retains those exact bytes for
// formatting so the file is not reopened later. It returns true for a physical
// file already seen (including the root), which both deduplicates symlink aliases
// and prevents directory-symlink cycles from recursively inserting more tokens.
// os.FileInfo values are retained to verify that each canonical pathname still
// identifies the file whose contents were parsed.
func discoverImportedFileContents(rootFile string, rootInput []byte, rootInfo os.FileInfo) ([]importedFile, error) {
	// Compare file identity rather than path spelling: lexical paths do not catch
	// imports such as dir/link/dir/link/Caddyfile through a symlink cycle.
	seen := []os.FileInfo{rootInfo}
	var files []importedFile

	// allTokens performs environment replacement in-place, so preserve the bytes
	// which FormatImports will subsequently pass to the formatter.
	inputCopy := append([]byte(nil), rootInput...)
	tokens, err := allTokens(rootFile, inputCopy)
	if err != nil {
		return nil, err
	}
	// Construct the parser exactly as parse() does. The import graph remains
	// responsible for logical snippet/import cycles; the observer below adds
	// physical-file identity handling for symlink aliases.
	p := parser{
		Dispenser: NewDispenser(tokens),
		importGraph: importGraph{
			nodes: make(map[string]struct{}),
			edges: make(adjacency),
		},
	}
	p.importObserver = func(path string, info os.FileInfo, content []byte) (bool, error) {
		// Returning skip=true tells doSingleImport not to insert this file's tokens
		// again. The first traversal already discovered any active descendants.
		for _, previous := range seen {
			if os.SameFile(previous, info) {
				return true, nil
			}
		}

		// Store one stable, absolute spelling for callers, but verify it still
		// resolves to the descriptor which supplied content before retaining it.
		canonical, err := canonicalPath(path)
		if err != nil {
			return false, err
		}
		currentInfo, err := os.Stat(canonical)
		if err != nil {
			return false, err
		}
		if !os.SameFile(info, currentInfo) {
			return false, fmt.Errorf("imported file changed while being read")
		}

		seen = append(seen, info)
		files = append(files, importedFile{
			path: canonical,
			// The parser owns its read buffer; keep an independent copy for the
			// formatting pass and avoid a second pathname-based read.
			content: append([]byte(nil), content...),
			info:    info,
		})
		return false, nil
	}

	if _, err := p.parseAll(); err != nil {
		return nil, err
	}
	return files, nil
}

// canonicalPath returns an absolute path with symlinks resolved. Canonical paths
// make the FormattedFile API consistent for the root and every imported file;
// physical deduplication still uses os.SameFile because spelling alone is not a
// portable file-identity test.
func canonicalPath(path string) (string, error) {
	abs, err := caddy.FastAbs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// FormattedFile is a file path paired with its formatted contents.
type FormattedFile struct {
	Path    string
	Content []byte
}

// FormatImports reads filename, formats it (honoring opts), then discovers all
// files reached by active import directives and formats each one independently
// at nesting-0 baseline. WrapUnbracedSite is always disabled for imported files
// because they are fragments, not standalone Caddyfiles.
//
// All returned paths are absolute, symlink-resolved paths. The root file is
// always first, followed by imported files in parser discovery order.
func FormatImports(filename string, opts FormatOptions) ([]FormattedFile, error) {
	// Keep the lexical absolute path for parser-relative import resolution, while
	// using the canonical path for opening and returning the root file. This
	// matches adaptation when the supplied Caddyfile itself is reached by symlink.
	rootLexicalPath, err := caddy.FastAbs(filename)
	if err != nil {
		return nil, err
	}
	rootPath, err := canonicalPath(filename)
	if err != nil {
		return nil, err
	}
	// Reading and statting one open descriptor binds rootBytes and rootInfo to the
	// same physical file. Separate ReadFile and Stat calls would permit a pathname
	// replacement between the two operations.
	root, err := os.Open(rootPath)
	if err != nil {
		return nil, err
	}
	rootInfo, err := root.Stat()
	if err != nil {
		root.Close()
		return nil, err
	}
	rootBytes, err := io.ReadAll(root)
	closeErr := root.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}

	discovered, err := discoverImportedFileContents(rootLexicalPath, rootBytes, rootInfo)
	if err != nil {
		return nil, err
	}

	results := make([]FormattedFile, 0, 1+len(discovered))
	results = append(results, FormattedFile{Path: rootPath, Content: FormatWithOptions(rootBytes, opts)})
	for _, file := range discovered {
		results = append(results, FormattedFile{
			Path:    file.path,
			Content: FormatWithOptions(file.content, FormatOptions{}),
		})
	}

	// Formatting can take long enough for a pathname to be replaced. Before
	// returning writable paths to the caller, ensure every one still identifies
	// the physical file whose bytes were parsed and formatted. The command layer
	// performs another check immediately before atomic replacement.
	for i, result := range results {
		currentInfo, err := os.Stat(result.Path)
		if err != nil {
			return nil, err
		}
		originalInfo := rootInfo
		if i > 0 {
			originalInfo = discovered[i-1].info
		}
		if !os.SameFile(originalInfo, currentInfo) {
			return nil, fmt.Errorf("file changed while formatting: %s", result.Path)
		}
	}

	return results, nil
}
