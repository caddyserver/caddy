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

func discoverImportedFileContents(rootFile string, rootInput []byte, rootInfo os.FileInfo) ([]importedFile, error) {
	seen := []os.FileInfo{rootInfo}
	var files []importedFile

	inputCopy := append([]byte(nil), rootInput...)
	tokens, err := allTokens(rootFile, inputCopy)
	if err != nil {
		return nil, err
	}
	p := parser{
		Dispenser: NewDispenser(tokens),
		importGraph: importGraph{
			nodes: make(map[string]struct{}),
			edges: make(adjacency),
		},
	}
	p.importObserver = func(path string, info os.FileInfo, content []byte) (bool, error) {
		for _, previous := range seen {
			if os.SameFile(previous, info) {
				return true, nil
			}
		}

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
			path:    canonical,
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
	rootLexicalPath, err := caddy.FastAbs(filename)
	if err != nil {
		return nil, err
	}
	rootPath, err := canonicalPath(filename)
	if err != nil {
		return nil, err
	}
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
