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

package fileserver

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/parser"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MatchFile{})
}

// MatchFile is an HTTP request matcher that can match
// requests based upon file existence.
//
// Upon matching, three new placeholders will be made
// available:
//
// - `{http.matchers.file.relative}` The root-relative
// path of the file. This is often useful when rewriting
// requests.
// - `{http.matchers.file.absolute}` The absolute path
// of the matched file.
// - `{http.matchers.file.type}` Set to "directory" if
// the matched file is a directory, "file" otherwise.
// - `{http.matchers.file.remainder}` Set to the remainder
// of the path if the path was split by `split_path`.
//
// Even though file matching may depend on the OS path
// separator, the placeholder values always use /.
type MatchFile struct {
	// The file system implementation to use. By default, the
	// local disk file system will be used.
	FileSystem string `json:"fs,omitempty"`

	// The root directory, used for creating absolute
	// file paths, and required when working with
	// relative paths; if not specified, `{http.vars.root}`
	// will be used, if set; otherwise, the current
	// directory is assumed. Accepts placeholders.
	Root string `json:"root,omitempty"`

	// The list of files to try. Each path here is
	// considered related to Root. If nil, the request
	// URL's path will be assumed. Files and
	// directories are treated distinctly, so to match
	// a directory, the filepath MUST end in a forward
	// slash `/`. To match a regular file, there must
	// be no trailing slash. Accepts placeholders. If
	// the policy is "first_exist", then an error may
	// be triggered as a fallback by configuring "="
	// followed by a status code number,
	// for example "=404".
	TryFiles []string `json:"try_files,omitempty"`

	// How to choose a file in TryFiles. Can be:
	//
	// - first_exist
	// - first_exist_fallback
	// - smallest_size
	// - largest_size
	// - most_recently_modified
	//
	// Default is first_exist.
	TryPolicy string `json:"try_policy,omitempty"`

	// A list of delimiters to use to split the path in two
	// when trying files. If empty, no splitting will
	// occur, and the path will be tried as-is. For each
	// split value, the left-hand side of the split,
	// including the split value, will be the path tried.
	// For example, the path `/remote.php/dav/` using the
	// split value `.php` would try the file `/remote.php`.
	// Each delimiter must appear at the end of a URI path
	// component in order to be used as a split delimiter.
	SplitPath []string `json:"split_path,omitempty"`

	fsmap caddy.FileSystems

	logger *zap.Logger

	celLiteralRoot  bool
	celLiteralFS    bool
	celLiteralFiles map[int]bool
}

// CaddyModule returns the Caddy module information.
func (MatchFile) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.file",
		New: func() caddy.Module { return new(MatchFile) },
	}
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	file <files...> {
//	    root      <path>
//	    try_files <files...>
//	    try_policy first_exist|smallest_size|largest_size|most_recently_modified
//	}
func (m *MatchFile) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// iterate to merge multiple matchers into one
	for d.Next() {
		m.TryFiles = append(m.TryFiles, d.RemainingArgs()...)
		for d.NextBlock(0) {
			switch d.Val() {
			case "root":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Root = d.Val()
			case "try_files":
				m.TryFiles = append(m.TryFiles, d.RemainingArgs()...)
				if len(m.TryFiles) == 0 {
					return d.ArgErr()
				}
			case "try_policy":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.TryPolicy = d.Val()
			case "split_path":
				m.SplitPath = d.RemainingArgs()
				if len(m.SplitPath) == 0 {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression file()
//	expression file({http.request.uri.path}, '/index.php')
//	expression file({'root': '/srv', 'try_files': [{http.request.uri.path}, '/index.php'], 'try_policy': 'first_exist', 'split_path': ['.php']})
//
// Runtime strings are literal paths; static strings retain placeholder and glob
// expansion. A concatenation involving runtime data is also a literal path.
func (MatchFile) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	requestType := cel.ObjectType("http.Request")

	matcherFactory := func(data ref.Val) (caddyhttp.RequestMatcherWithError, error) {
		values, err := caddyhttp.CELValueToMapStrList(data)
		if err != nil {
			return nil, err
		}

		var root string
		if len(values["root"]) > 0 {
			root = values["root"][0]
		}

		var fsName string
		if len(values["fs"]) > 0 {
			fsName = values["fs"][0]
		}

		var try_policy string
		if len(values["try_policy"]) > 0 {
			try_policy = values["try_policy"][0]
		}

		m := MatchFile{
			Root:       root,
			TryFiles:   values["try_files"],
			TryPolicy:  try_policy,
			SplitPath:  values["split_path"],
			FileSystem: fsName,
		}
		mapping := data.(traits.Mapper)
		if v, found := mapping.Find(types.String("root")); found {
			m.celLiteralRoot = root != "" && caddyhttp.CELMatcherIsLiteral(v)
		}
		if v, found := mapping.Find(types.String("fs")); found {
			m.celLiteralFS = fsName != "" && caddyhttp.CELMatcherIsLiteral(v)
		}
		if v, found := mapping.Find(types.String("try_files")); found {
			m.celLiteralFiles = make(map[int]bool)
			if list, ok := v.(traits.Lister); ok {
				for i := types.Int(0); i < list.Size().(types.Int); i++ {
					m.celLiteralFiles[int(i)] = caddyhttp.CELMatcherIsLiteral(list.Get(i))
				}
			} else {
				m.celLiteralFiles[0] = caddyhttp.CELMatcherIsLiteral(v)
			}
		}

		err = m.Provision(ctx)
		return m, err
	}

	envOptions := []cel.EnvOption{
		cel.Macros(parser.NewGlobalVarArgMacro("file", celFileMatcherMacroExpander())),
		cel.Function("file", cel.Overload("file_request_map", []*cel.Type{requestType, caddyhttp.CELTypeJSON}, cel.BoolType)),
		cel.Function("file_request_map",
			cel.Overload("file_request_map", []*cel.Type{requestType, caddyhttp.CELTypeJSON}, cel.BoolType),
			cel.SingletonBinaryBinding(caddyhttp.CELMatcherRuntimeFunction("file_request_map", caddyhttp.CELMatcherLiteralFactory(matcherFactory)))),
	}

	programOptions := []cel.ProgramOption{
		cel.CustomDecorator(caddyhttp.CELMatcherDecorator("file_request_map", matcherFactory)),
	}

	return caddyhttp.NewMatcherCELLibrary(envOptions, programOptions), nil
}

func celFileMatcherMacroExpander() parser.MacroExpander {
	return func(eh parser.ExprHelper, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
		if len(args) == 0 {
			return eh.NewCall("file",
				eh.NewIdent(caddyhttp.CELRequestVarName),
				eh.NewMap(),
			), nil
		}
		if len(args) == 1 {
			arg := args[0]
			if isCELStringExpr(arg) {
				return eh.NewCall("file",
					eh.NewIdent(caddyhttp.CELRequestVarName),
					eh.NewMap(eh.NewMapEntry(
						eh.NewLiteral(types.String("try_files")),
						caddyhttp.CELMatcherArgument(eh, eh.NewList(arg)),
						false,
					)),
				), nil
			}
			if isCELTryFilesLiteral(arg) {
				return eh.NewCall("file", eh.NewIdent(caddyhttp.CELRequestVarName), caddyhttp.CELMatcherArgument(eh, arg)), nil
			}
			return nil, &common.Error{
				Location: eh.OffsetLocation(arg.ID()),
				Message:  "matcher requires either a map or string literal argument",
			}
		}

		for _, arg := range args {
			if !isCELStringExpr(arg) {
				return nil, &common.Error{
					Location: eh.OffsetLocation(arg.ID()),
					Message:  "matcher only supports repeated string literal arguments",
				}
			}
		}
		return eh.NewCall("file",
			eh.NewIdent(caddyhttp.CELRequestVarName),
			eh.NewMap(eh.NewMapEntry(
				eh.NewLiteral(types.String("try_files")),
				caddyhttp.CELMatcherArgument(eh, eh.NewList(args...)),
				false,
			)),
		), nil
	}
}

// Provision sets up m's defaults.
func (m *MatchFile) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	m.fsmap = ctx.FileSystems()

	if m.Root == "" {
		m.Root = "{http.vars.root}"
	}

	if m.FileSystem == "" {
		m.FileSystem = "{http.vars.fs}"
	}

	// if list of files to try was omitted entirely, assume URL path
	// (use placeholder instead of r.URL.Path; see issue #4146)
	if m.TryFiles == nil {
		m.TryFiles = []string{"{http.request.uri.path}"}
	}
	return nil
}

// Validate ensures m has a valid configuration.
func (m MatchFile) Validate() error {
	switch m.TryPolicy {
	case "",
		tryPolicyFirstExist,
		tryPolicyFirstExistFallback,
		tryPolicyLargestSize,
		tryPolicySmallestSize,
		tryPolicyMostRecentlyMod:
	default:
		return fmt.Errorf("unknown try policy %s", m.TryPolicy)
	}
	return nil
}

// Match returns true if r matches m. Returns true
// if a file was matched. If so, four placeholders
// will be available:
//   - http.matchers.file.relative: Slash-prefixed path to file relative to site root
//   - http.matchers.file.absolute: Path to file including site root
//   - http.matchers.file.type: file or directory
//   - http.matchers.file.remainder: Portion remaining after splitting file path (if configured)
func (m MatchFile) Match(r *http.Request) bool {
	match, err := m.selectFile(r)
	if err != nil {
		// nolint:staticcheck
		caddyhttp.SetVar(r.Context(), caddyhttp.MatcherErrorVarKey, err)
	}
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchFile) MatchWithError(r *http.Request) (bool, error) {
	return m.selectFile(r)
}

// selectFile chooses a file according to m.TryPolicy by appending
// the paths in m.TryFiles to m.Root, with placeholder replacements.
func (m MatchFile) selectFile(r *http.Request) (bool, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	root := m.Root
	if !m.celLiteralRoot {
		root = repl.ReplaceAll(root, ".")
	}
	root = filepath.Clean(root)

	fsName := m.FileSystem
	if !m.celLiteralFS {
		fsName = repl.ReplaceAll(fsName, "")
	}

	fileSystem, ok := m.fsmap.Get(fsName)
	if !ok {
		if c := m.logger.Check(zapcore.ErrorLevel, "use of unregistered filesystem"); c != nil {
			c.Write(zap.String("fs", fsName))
		}
		return false, nil
	}
	type matchCandidate struct {
		fullpath, relative, splitRemainder string
	}
	makeCandidate := func(fullpath, remainder string) (matchCandidate, bool) {
		relative, err := filepath.Rel(root, fullpath)
		if err != nil {
			m.logger.Error("making root-relative file path", zap.String("path", fullpath), zap.Error(err))
			return matchCandidate{}, false
		}
		if relative == "." {
			relative = ""
		}
		relative = "/" + filepath.ToSlash(relative)
		if strings.HasSuffix(fullpath, separator) && !strings.HasSuffix(relative, "/") {
			relative += "/"
		}
		return matchCandidate{fullpath: fullpath, relative: relative, splitRemainder: remainder}, true
	}

	// makeCandidates evaluates placeholders in file and expands any glob expressions
	// to build a list of file candidates. Special glob characters are escaped in
	// placeholder replacements so globs cannot be expanded from placeholders, and
	// globs are not evaluated on Windows because of its path separator character:
	// escaping is not supported so we can't safely glob on Windows, or we can't
	// support placeholders on Windows (pick one). (Actually, evaluating untrusted
	// globs is not the end of the world since the file server will still hide any
	// hidden files, it just might lead to unexpected behavior.)
	makeCandidates := func(file string, literal bool) []matchCandidate {
		// first, evaluate placeholders in the file pattern
		expandedFile := file
		var err error
		if literal {
			if runtime.GOOS != "windows" {
				expandedFile = globSafeRepl.Replace(file)
			}
		} else {
			expandedFile, err = repl.ReplaceFunc(file, func(variable string, val any) (any, error) {
				if runtime.GOOS == "windows" {
					return val, nil
				}
				switch v := val.(type) {
				case string:
					return globSafeRepl.Replace(v), nil
				case fmt.Stringer:
					return globSafeRepl.Replace(v.String()), nil
				}
				return val, nil
			})
		}
		if err != nil {
			if c := m.logger.Check(zapcore.ErrorLevel, "evaluating placeholders"); c != nil {
				c.Write(zap.Error(err))
			}

			expandedFile = file // "oh well," I guess?
		}

		// we must split before globbing so that the file system
		// doesn't include the remainder ("afterSplit") in the filename
		beforeSplit, afterSplit, ok := m.cleanSplit(file, expandedFile)
		if !ok {
			return nil
		}

		// create the full path to the file by prepending the site root
		globRoot := root
		if runtime.GOOS != "windows" {
			globRoot = globSafeRepl.Replace(root)
		}
		fullPattern := caddyhttp.SanitizedPathJoin(globRoot, beforeSplit)

		// expand glob expressions, but not on Windows because Glob() doesn't
		// support escaping on Windows due to path separator)
		var globResults []string
		if runtime.GOOS == "windows" {
			globResults = []string{fullPattern} // precious Windows
		} else {
			globResults, err = fs.Glob(fileSystem, fullPattern)
			if err != nil {
				if c := m.logger.Check(zapcore.ErrorLevel, "expanding glob"); c != nil {
					c.Write(zap.Error(fmt.Errorf("%w: %s", err, fullPattern)))
				}
			}
		}

		// for each glob result, combine all the forms of the path
		candidates := make([]matchCandidate, 0, len(globResults))
		for _, result := range globResults {
			if candidate, ok := makeCandidate(result, afterSplit); ok {
				candidates = append(candidates, candidate)
			}
		}

		return candidates
	}

	// makeLiteralCandidate builds a candidate from file as a literal path,
	// without expanding globs or checking that the file exists. It is used only
	// for the final entry of first_exist_fallback, which matches unconditionally
	// even when globbing found nothing because the file is absent.
	makeLiteralCandidate := func(file string, literal bool) (matchCandidate, bool) {
		// placeholders are not glob-escaped here, since nothing is globbed;
		// errors were already logged by makeCandidates for the same pattern
		expandedFile := file
		if !literal {
			var err error
			expandedFile, err = repl.ReplaceFunc(file, func(_ string, val any) (any, error) {
				return val, nil
			})
			if err != nil {
				expandedFile = file
			}
		}
		beforeSplit, afterSplit, ok := m.cleanSplit(file, expandedFile)
		if !ok {
			return matchCandidate{}, false
		}
		fullPath := caddyhttp.SanitizedPathJoin(root, beforeSplit)
		return makeCandidate(fullPath, afterSplit)
	}

	// setPlaceholders creates the placeholders for the matched file
	setPlaceholders := func(candidate matchCandidate, isDir bool) {
		repl.Set("http.matchers.file.relative", filepath.ToSlash(candidate.relative))
		repl.Set("http.matchers.file.absolute", filepath.ToSlash(candidate.fullpath))
		repl.Set("http.matchers.file.remainder", filepath.ToSlash(candidate.splitRemainder))

		fileType := "file"
		if isDir {
			fileType = "directory"
		}
		repl.Set("http.matchers.file.type", fileType)
	}

	// match file according to the configured policy
	switch m.TryPolicy {
	case "", tryPolicyFirstExist, tryPolicyFirstExistFallback:
		maxI := -1
		if m.TryPolicy == tryPolicyFirstExistFallback {
			maxI = len(m.TryFiles) - 1
		}

		for i, pattern := range m.TryFiles {
			// If the pattern is a status code, emit an error,
			// which short-circuits the middleware pipeline and
			// writes an HTTP error response.
			if !m.celLiteralFiles[i] {
				if err := parseErrorCode(pattern); err != nil {
					return false, err
				}
			}

			candidates := makeCandidates(pattern, m.celLiteralFiles[i])
			// globbing finds only files that exist, but the fallback entry matches anyway
			if i == maxI && len(candidates) == 0 {
				if c, ok := makeLiteralCandidate(pattern, m.celLiteralFiles[i]); ok {
					candidates = []matchCandidate{c}
				}
			}
			for _, c := range candidates {
				// Skip the IO if using fallback policy and it's the latest item
				if i == maxI {
					setPlaceholders(c, false)

					return true, nil
				}

				if info, exists := m.strictFileExists(fileSystem, c.fullpath); exists {
					setPlaceholders(c, info.IsDir())
					return true, nil
				}
			}
		}

	case tryPolicyLargestSize:
		var largestSize int64
		var largest matchCandidate
		var largestInfo os.FileInfo
		for i, pattern := range m.TryFiles {
			candidates := makeCandidates(pattern, m.celLiteralFiles[i])
			for _, c := range candidates {
				info, err := fs.Stat(fileSystem, c.fullpath)
				if err == nil && (largestInfo == nil || info.Size() > largestSize) {
					largestSize = info.Size()
					largest = c
					largestInfo = info
				}
			}
		}
		if largestInfo == nil {
			return false, nil
		}
		setPlaceholders(largest, largestInfo.IsDir())
		return true, nil

	case tryPolicySmallestSize:
		var smallestSize int64
		var smallest matchCandidate
		var smallestInfo os.FileInfo
		for i, pattern := range m.TryFiles {
			candidates := makeCandidates(pattern, m.celLiteralFiles[i])
			for _, c := range candidates {
				info, err := fs.Stat(fileSystem, c.fullpath)
				if err == nil && (smallestInfo == nil || info.Size() < smallestSize) {
					smallestSize = info.Size()
					smallest = c
					smallestInfo = info
				}
			}
		}
		if smallestInfo == nil {
			return false, nil
		}
		setPlaceholders(smallest, smallestInfo.IsDir())
		return true, nil

	case tryPolicyMostRecentlyMod:
		var recent matchCandidate
		var recentInfo os.FileInfo
		for i, pattern := range m.TryFiles {
			candidates := makeCandidates(pattern, m.celLiteralFiles[i])
			for _, c := range candidates {
				info, err := fs.Stat(fileSystem, c.fullpath)
				if err == nil &&
					(recentInfo == nil || info.ModTime().After(recentInfo.ModTime())) {
					recent = c
					recentInfo = info
				}
			}
		}
		if recentInfo == nil {
			return false, nil
		}
		setPlaceholders(recent, recentInfo.IsDir())
		return true, nil
	}

	return false, nil
}

// parseErrorCode checks if the input is a status
// code number, prefixed by "=", and returns an
// error if so.
func parseErrorCode(input string) error {
	if len(input) > 1 && input[0] == '=' {
		code, err := strconv.Atoi(input[1:])
		if err != nil || code < 100 || code > 999 {
			return nil
		}
		return caddyhttp.Error(code, fmt.Errorf("%s", input[1:]))
	}
	return nil
}

// strictFileExists returns true if file exists
// and matches the convention of the given file
// path. If the path ends in a forward slash,
// the file must also be a directory; if it does
// NOT end in a forward slash, the file must NOT
// be a directory.
func (m MatchFile) strictFileExists(fileSystem fs.FS, file string) (os.FileInfo, bool) {
	info, err := fs.Stat(fileSystem, file)
	if err != nil {
		// in reality, this can be any error
		// such as permission or even obscure
		// ones like "is not a directory" (when
		// trying to stat a file within a file);
		// in those cases we can't be sure if
		// the file exists, so we just treat any
		// error as if it does not exist; see
		// https://stackoverflow.com/a/12518877/1048862
		return nil, false
	}
	if strings.HasSuffix(file, separator) {
		// by convention, file paths ending
		// in a path separator must be a directory
		return info, info.IsDir()
	}
	// by convention, file paths NOT ending
	// in a path separator must NOT be a directory
	return info, !info.IsDir()
}

// cleanSplit cleans expanded, the expansion of pattern, and splits it if
// configured. It keeps the trailing slash so that "/file/" or "/file/./"
// cannot match a regular file, and reports false for a path ending in "/"
// unless pattern does too, since only such patterns match a directory.
func (m MatchFile) cleanSplit(pattern, expanded string) (beforeSplit, afterSplit string, ok bool) {
	cleaned := caddyhttp.NormalizedPath(expanded, true)
	if cleaned == "" {
		// Preserve path.Clean's existing result for an empty path.
		cleaned = "."
	}
	beforeSplit, afterSplit = m.firstSplit(cleaned)
	patternHasTrailingSlash := strings.HasSuffix(pattern, "/")
	// SanitizedPathJoin cleans the doubled slash but uses it to preserve
	// the filesystem separator after the site root.
	if beforeSplit == "/" && patternHasTrailingSlash {
		beforeSplit += "/"
	}

	// with "{path}", a request for "/dir/" falls through to the next entry (e.g. "{path}/index.php")
	if beforeSplit != "/" && strings.HasSuffix(beforeSplit, "/") && !patternHasTrailingSlash {
		return "", "", false
	}
	return beforeSplit, afterSplit, true
}

// firstSplit returns the first result where the path
// can be split in two by a value in m.SplitPath. The
// return values are the first piece of the path that
// ends with the split substring and the remainder.
// If the path cannot be split, the path is returned
// as-is (with no remainder).
func (m MatchFile) firstSplit(path string) (splitPart, remainder string) {
	for _, split := range m.SplitPath {
		if idx := indexFold(path, split); idx > -1 {
			pos := idx + len(split)
			// skip the split if it's not the final part of the filename
			if pos != len(path) && !strings.HasPrefix(path[pos:], "/") {
				continue
			}
			return path[:pos], path[pos:]
		}
	}
	return path, ""
}

// There is no strings.IndexFold() function like there is strings.EqualFold(),
// but we can use strings.EqualFold() to build our own case-insensitive
// substring search (as of Go 1.14).
func indexFold(haystack, needle string) int {
	nlen := len(needle)
	for i := 0; i+nlen < len(haystack); i++ {
		if strings.EqualFold(haystack[i:i+nlen], needle) {
			return i
		}
	}
	return -1
}

// isCELTryFilesLiteral returns whether the expression resolves to a map literal containing
// only string keys with or a placeholder call.
func isCELTryFilesLiteral(e ast.Expr) bool {
	switch e.Kind() {
	case ast.MapKind:
		mapExpr := e.AsMap()
		for _, entry := range mapExpr.Entries() {
			mapKey := entry.AsMapEntry().Key()
			mapVal := entry.AsMapEntry().Value()
			if !isCELStringLiteral(mapKey) {
				return false
			}
			mapKeyStr := mapKey.AsLiteral().ConvertToType(types.StringType).Value()
			switch mapKeyStr {
			case "try_files", "split_path":
				if !isCELStringListLiteral(mapVal) {
					return false
				}
			case "try_policy", "root", "fs":
				if !isCELStringExpr(mapVal) {
					return false
				}
			default:
				return false
			}
		}
		return true

	case ast.UnspecifiedExprKind, ast.CallKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.LiteralKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// isCELStringExpr indicates whether the expression is a supported string expression
func isCELStringExpr(e ast.Expr) bool {
	return isCELStringLiteral(e) || isCELCaddyPlaceholderCall(e) || isCELConcatCall(e)
}

// isCELStringLiteral returns whether the expression is a CEL string literal.
func isCELStringLiteral(e ast.Expr) bool {
	switch e.Kind() {
	case ast.LiteralKind:
		constant := e.AsLiteral()
		switch constant.Type() {
		case types.StringType:
			return true
		}
	case ast.UnspecifiedExprKind, ast.CallKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// isCELCaddyPlaceholderCall returns whether the expression is a caddy placeholder call.
func isCELCaddyPlaceholderCall(e ast.Expr) bool {
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		if call.FunctionName() == caddyhttp.CELPlaceholderFuncName {
			return true
		}
	case ast.UnspecifiedExprKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.LiteralKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// isCELConcatCall tests whether the expression is a concat function (+) with string, placeholder, or
// other concat call arguments.
func isCELConcatCall(e ast.Expr) bool {
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		if call.Target().Kind() != ast.UnspecifiedExprKind {
			return false
		}
		if call.FunctionName() != operators.Add {
			return false
		}
		for _, arg := range call.Args() {
			if !isCELStringExpr(arg) {
				return false
			}
		}
		return true
	case ast.UnspecifiedExprKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.LiteralKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// isCELStringListLiteral returns whether the expression resolves to a list literal
// containing only string constants or a placeholder call.
func isCELStringListLiteral(e ast.Expr) bool {
	switch e.Kind() {
	case ast.ListKind:
		list := e.AsList()
		for _, elem := range list.Elements() {
			if !isCELStringExpr(elem) {
				return false
			}
		}
		return true
	case ast.UnspecifiedExprKind, ast.CallKind, ast.ComprehensionKind, ast.IdentKind, ast.LiteralKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// globSafeRepl replaces special glob characters with escaped
// equivalents. Note that the filepath godoc states that
// escaping is not done on Windows because of the separator.
var globSafeRepl = strings.NewReplacer(
	"*", "\\*",
	"[", "\\[",
	"?", "\\?",
	"\\", "\\\\",
)

const (
	tryPolicyFirstExist         = "first_exist"
	tryPolicyFirstExistFallback = "first_exist_fallback"
	tryPolicyLargestSize        = "largest_size"
	tryPolicySmallestSize       = "smallest_size"
	tryPolicyMostRecentlyMod    = "most_recently_modified"
)

// Interface guards
var (
	_ caddy.Validator                   = (*MatchFile)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchFile)(nil)
	_ caddyhttp.CELLibraryProducer      = (*MatchFile)(nil)
)
