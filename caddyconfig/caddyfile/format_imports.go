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
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// importCandidate is a single `import <arg>` occurrence found in a file. It
// records enough to (a) classify the arg as a snippet vs a file import once the
// full snippet set is known, and (b) resolve the arg relative to the file it
// appears in.
type importCandidate struct {
	importer string // the file the import directive appears in
	arg      string // the (env-substituted) import argument
}

// discoverImportedFiles returns the set of files reachable via file-imports
// from rootFile, in deterministic (discovery) order, deduped by caddy.FastAbs,
// cycle-safe, and EXCLUDING the root itself.
//
// It replicates the relevant parse-time behaviors so the set matches what the
// parser would actually import:
//
//   - `import` is a directive only when it is the first token of its line
//     (parse.go's `isNewLine()` checks). A stray `import` token elsewhere on a
//     line (e.g. `basic_auth / import password`) is an argument, not a directive.
//   - The import argument is env-substituted (via replaceEnvVars) before its
//     glob is resolved, matching allTokens' pre-tokenize substitution.
//   - Snippet names `(name)` are token-identical to filenames and may be defined
//     in OTHER imported files, so snippet names are collected across the whole
//     reachable graph before an `import <arg>` is classified as a file import.
//   - `{block}` / `{blocks.*}` placeholder args are skipped.
//   - A non-glob file import missing on disk is skipped with a Warn, not an
//     error (preserving back-compat with plain `caddy fmt`).
func discoverImportedFiles(rootFile string, rootInput []byte) (files []string, err error) {
	rootAbs, err := caddy.FastAbs(rootFile)
	if err != nil {
		return nil, err
	}

	// Round 1: walk the full reachable file set. We resolve file imports as we
	// go so we can reach files that define snippets used elsewhere. Along the
	// way we collect every snippet name defined anywhere in the graph and every
	// import candidate we encounter.
	//
	// visited maps abs path -> the on-disk path we discovered it as (for the
	// result), and doubles as the cycle guard. order preserves discovery order.
	visited := map[string]string{rootAbs: rootFile}
	var order []string // abs paths, in discovery order, excluding root
	snippetNames := map[string]struct{}{}
	var candidates []importCandidate

	// worklist holds files still to be scanned; each entry is the on-disk path.
	worklist := []struct {
		file  string
		input []byte
	}{{file: rootFile, input: rootInput}}

	for len(worklist) > 0 {
		item := worklist[0]
		worklist = worklist[1:]

		tokens, lexErr := Lex(item.input, item.file, LexOptions{})
		if lexErr != nil {
			return nil, lexErr
		}

		snips, imports := scanTokens(tokens)
		for _, name := range snips {
			snippetNames[name] = struct{}{}
		}

		for _, imp := range imports {
			candidates = append(candidates, importCandidate{importer: item.file, arg: imp})

			// To discover the full file set (including files that define
			// snippets referenced elsewhere), we follow this candidate as a
			// file import unless its arg is already known to be a snippet. Args
			// that turn out to be snippets defined in later files are filtered
			// out in round 2.
			if _, isSnippet := snippetNames[imp]; isSnippet {
				continue
			}
			if isBlockPlaceholder(imp) {
				continue
			}

			// Note: no warning here. Round 1 may run before a file that
			// defines this arg as a snippet has been scanned, so a
			// zero-match arg is not necessarily a missing file yet. The
			// authoritative missing-file warning is emitted in round 2.
			matches, _, resolveErr := resolveImportGlob(item.file, string(replaceEnvVars([]byte(imp))))
			if resolveErr != nil {
				return nil, resolveErr
			}

			for _, match := range matches {
				matchAbs, absErr := caddy.FastAbs(match)
				if absErr != nil {
					return nil, absErr
				}
				if _, seen := visited[matchAbs]; seen {
					continue
				}
				visited[matchAbs] = match
				order = append(order, matchAbs)

				input, readErr := os.ReadFile(match)
				if readErr != nil {
					// Missing/unreadable at scan time: skip with a warning
					// rather than hard-failing, matching import back-compat.
					caddy.Log().Warn("Could not read imported file", zap.String("file", match), zap.Error(readErr))
					continue
				}
				worklist = append(worklist, struct {
					file  string
					input []byte
				}{file: match, input: input})
			}
		}
	}

	// Round 2: with the complete snippet set known, decide which discovered
	// files are genuinely reachable via file imports. A file is kept if it is
	// reachable from a candidate whose arg is NOT a known snippet name (or via a
	// glob, which is never a snippet). Files reachable ONLY through an arg that
	// is actually a snippet name are dropped.
	kept := map[string]struct{}{}
	// Seed with root; propagate reachability through candidates.
	reachable := map[string]struct{}{rootAbs: {}}
	warned := map[string]struct{}{} // dedupe missing-file warnings across fixed-point rounds
	// Fixed-point: keep expanding while new importers become reachable.
	for {
		grew := false
		for _, c := range candidates {
			importerAbs, absErr := caddy.FastAbs(c.importer)
			if absErr != nil {
				return nil, absErr
			}
			if _, ok := reachable[importerAbs]; !ok {
				continue
			}
			// A file import only if the arg is not a snippet name.
			if _, isSnippet := snippetNames[c.arg]; isSnippet {
				continue
			}
			if isBlockPlaceholder(c.arg) {
				continue
			}
			matches, globPattern, resolveErr := resolveImportGlob(c.importer, string(replaceEnvVars([]byte(c.arg))))
			if resolveErr != nil {
				return nil, resolveErr
			}
			if len(matches) == 0 {
				// A non-glob file import that resolves to nothing is a
				// missing file: warn but do not fail (back-compat with
				// plain `caddy fmt`). A glob with no matches is silent.
				if !strings.ContainsAny(globPattern, "*?[]") {
					key := c.importer + "\x00" + c.arg
					if _, done := warned[key]; !done {
						warned[key] = struct{}{}
						caddy.Log().Warn("File to import not found", zap.String("import", c.arg))
					}
				}
				continue
			}
			for _, match := range matches {
				matchAbs, mErr := caddy.FastAbs(match)
				if mErr != nil {
					return nil, mErr
				}
				if _, ok := reachable[matchAbs]; !ok {
					reachable[matchAbs] = struct{}{}
					grew = true
				}
				kept[matchAbs] = struct{}{}
			}
		}
		if !grew {
			break
		}
	}

	// Emit in discovery order, deduped, excluding the root, keeping only files
	// that survived round-2 classification.
	for _, abs := range order {
		if abs == rootAbs {
			continue
		}
		if _, ok := kept[abs]; !ok {
			continue
		}
		files = append(files, visited[abs])
	}

	return files, nil
}

// scanTokens walks a file's tokens once and returns the snippet names defined
// in it and the (raw) arguments of `import` directives found in it. An `import`
// is only recognized when it is the first token of its line. A snippet
// definition is a first-of-line `(name)` token followed by an open brace.
func scanTokens(tokens []Token) (snippets []string, imports []string) {
	for i := range len(tokens) {
		tok := tokens[i]
		firstOfLine := i == 0 || isNextOnNewLine(tokens[i-1], tok)
		if !firstOfLine {
			continue
		}

		// snippet definition: (name) followed by '{'
		if len(tok.Text) >= 3 && strings.HasPrefix(tok.Text, "(") && strings.HasSuffix(tok.Text, ")") {
			if i+1 < len(tokens) && isOpenCurlyBrace(tokens[i+1]) && !isNextOnNewLine(tok, tokens[i+1]) {
				snippets = append(snippets, strings.TrimSuffix(tok.Text[1:], ")"))
			}
			continue
		}

		// import directive: first-of-line `import` with a same-line argument
		if tok.Text == "import" && tok.wasQuoted == 0 {
			if i+1 < len(tokens) && !isNextOnNewLine(tok, tokens[i+1]) {
				imports = append(imports, tokens[i+1].Text)
			}
		}
	}
	return snippets, imports
}

// isBlockPlaceholder reports whether an import argument is a {block} or
// {blocks.*} placeholder (substituted by the parser, not a file). Note that
// {$ENV} args are file globs, not block placeholders.
func isBlockPlaceholder(arg string) bool {
	if arg == "{block}" {
		return true
	}
	return strings.HasPrefix(arg, "{blocks.") && strings.HasSuffix(arg, "}")
}

// FormattedFile is a file path paired with its formatted contents.
type FormattedFile struct {
	Path    string
	Content []byte
}

// FormatImports reads filename, formats it (honoring opts), then discovers all
// files reachable via its import directives and formats each one independently
// at nesting-0 baseline (WrapUnbracedSite always forced OFF for imported files,
// since they are fragments, not standalone Caddyfiles).
//
// The root file is always first in the returned slice, followed by discovered
// files in discovery order. If a discovered file cannot be read it is skipped
// with a warning log so that one bad import does not abort the whole run.
func FormatImports(filename string, opts FormatOptions) ([]FormattedFile, error) {
	rootBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	formattedRoot := FormatWithOptions(rootBytes, opts)

	discovered, err := discoverImportedFiles(filename, rootBytes)
	if err != nil {
		return nil, err
	}

	results := make([]FormattedFile, 0, 1+len(discovered))
	results = append(results, FormattedFile{Path: filename, Content: formattedRoot})

	for _, path := range discovered {
		fileBytes, readErr := os.ReadFile(path)
		if readErr != nil {
			// Warn and skip rather than failing the entire run; keeps caddy fmt
			// robust when one imported file is temporarily missing or unreadable.
			caddy.Log().Warn("Could not read imported file for formatting", zap.String("file", path), zap.Error(readErr))
			continue
		}
		// WrapUnbracedSite is always OFF for imported files: they are fragments,
		// not standalone Caddyfiles, so wrapping would be incorrect.
		formatted := FormatWithOptions(fileBytes, FormatOptions{})
		results = append(results, FormattedFile{Path: path, Content: formatted})
	}

	return results, nil
}
