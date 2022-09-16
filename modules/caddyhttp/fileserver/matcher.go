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
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/parser"
	"go.uber.org/zap"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
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
	FileSystemRaw json.RawMessage `json:"file_system,omitempty" caddy:"namespace=caddy.fs inline_key=backend"`
	fileSystem    fs.FS

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

	logger *zap.Logger
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
//	expression file({'root': '/srv', 'try_files': [{http.request.uri.path}, '/index.php'], 'try_policy': 'first_exist', 'split_path': ['.php']})
func (MatchFile) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	requestType := cel.ObjectType("http.Request")

	matcherFactory := func(data ref.Val) (caddyhttp.RequestMatcher, error) {
		values, err := caddyhttp.CELValueToMapStrList(data)
		if err != nil {
			return nil, err
		}

		var root string
		if len(values["root"]) > 0 {
			root = values["root"][0]
		}

		var try_policy string
		if len(values["try_policy"]) > 0 {
			root = values["try_policy"][0]
		}

		m := MatchFile{
			Root:      root,
			TryFiles:  values["try_files"],
			TryPolicy: try_policy,
			SplitPath: values["split_path"],
		}

		err = m.Provision(ctx)
		return m, err
	}

	envOptions := []cel.EnvOption{
		cel.Macros(parser.NewGlobalVarArgMacro("file", celFileMatcherMacroExpander())),
		cel.Function("file", cel.Overload("file_request_map", []*cel.Type{requestType, caddyhttp.CELTypeJSON}, cel.BoolType)),
		cel.Function("file_request_map",
			cel.Overload("file_request_map", []*cel.Type{requestType, caddyhttp.CELTypeJSON}, cel.BoolType),
			cel.SingletonBinaryImpl(caddyhttp.CELMatcherRuntimeFunction("file_request_map", matcherFactory))),
	}

	programOptions := []cel.ProgramOption{
		cel.CustomDecorator(caddyhttp.CELMatcherDecorator("file_request_map", matcherFactory)),
	}

	return caddyhttp.NewMatcherCELLibrary(envOptions, programOptions), nil
}

func celFileMatcherMacroExpander() parser.MacroExpander {
	return func(eh parser.ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
		if len(args) == 0 {
			return nil, &common.Error{
				Message: "matcher requires at least one argument",
			}
		}
		if len(args) == 1 {
			arg := args[0]
			if isCELStringLiteral(arg) || isCELCaddyPlaceholderCall(arg) {
				return eh.GlobalCall("file",
					eh.Ident("request"),
					eh.NewMap(
						eh.NewMapEntry(eh.LiteralString("try_files"), eh.NewList(arg)),
					),
				), nil
			}
			if isCELTryFilesLiteral(arg) {
				return eh.GlobalCall("file", eh.Ident("request"), arg), nil
			}
			return nil, &common.Error{
				Location: eh.OffsetLocation(arg.GetId()),
				Message:  "matcher requires either a map or string literal argument",
			}
		}

		for _, arg := range args {
			if !(isCELStringLiteral(arg) || isCELCaddyPlaceholderCall(arg)) {
				return nil, &common.Error{
					Location: eh.OffsetLocation(arg.GetId()),
					Message:  "matcher only supports repeated string literal arguments",
				}
			}
		}
		return eh.GlobalCall("file",
			eh.Ident("request"),
			eh.NewMap(
				eh.NewMapEntry(
					eh.LiteralString("try_files"), eh.NewList(args...),
				),
			),
		), nil
	}
}

// Provision sets up m's defaults.
func (m *MatchFile) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	// establish the file system to use
	if len(m.FileSystemRaw) > 0 {
		mod, err := ctx.LoadModule(m, "FileSystemRaw")
		if err != nil {
			return fmt.Errorf("loading file system module: %v", err)
		}
		m.fileSystem = mod.(fs.FS)
	}
	if m.fileSystem == nil {
		m.fileSystem = osFS{}
	}

	if m.Root == "" {
		m.Root = "{http.vars.root}"
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
//   - http.matchers.file.relative: Path to file relative to site root
//   - http.matchers.file.absolute: Path to file including site root
//   - http.matchers.file.type: file or directory
//   - http.matchers.file.remainder: Portion remaining after splitting file path (if configured)
func (m MatchFile) Match(r *http.Request) bool {
	return m.selectFile(r)
}

// selectFile chooses a file according to m.TryPolicy by appending
// the paths in m.TryFiles to m.Root, with placeholder replacements.
func (m MatchFile) selectFile(r *http.Request) (matched bool) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	root := filepath.Clean(repl.ReplaceAll(m.Root, "."))

	type matchCandidate struct {
		fullpath, relative, splitRemainder string
	}

	// makeCandidates evaluates placeholders in file and expands any glob expressions
	// to build a list of file candidates. Special glob characters are escaped in
	// placeholder replacements so globs cannot be expanded from placeholders, and
	// globs are not evaluated on Windows because of its path separator character:
	// escaping is not supported so we can't safely glob on Windows, or we can't
	// support placeholders on Windows (pick one). (Actually, evaluating untrusted
	// globs is not the end of the world since the file server will still hide any
	// hidden files, it just might lead to unexpected behavior.)
	makeCandidates := func(file string) []matchCandidate {
		// first, evaluate placeholders in the file pattern
		expandedFile, err := repl.ReplaceFunc(file, func(variable string, val any) (any, error) {
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
		if err != nil {
			m.logger.Error("evaluating placeholders", zap.Error(err))
			expandedFile = file // "oh well," I guess?
		}

		// clean the path and split, if configured -- we must split before
		// globbing so that the file system doesn't include the remainder
		// ("afterSplit") in the filename; be sure to restore trailing slash
		beforeSplit, afterSplit := m.firstSplit(path.Clean(expandedFile))
		if strings.HasSuffix(file, "/") {
			beforeSplit += "/"
		}

		// create the full path to the file by prepending the site root
		fullPattern := caddyhttp.SanitizedPathJoin(root, beforeSplit)

		// expand glob expressions, but not on Windows because Glob() doesn't
		// support escaping on Windows due to path separator)
		var globResults []string
		if runtime.GOOS == "windows" {
			globResults = []string{fullPattern} // precious Windows
		} else {
			globResults, err = fs.Glob(m.fileSystem, fullPattern)
			if err != nil {
				m.logger.Error("expanding glob", zap.Error(err))
			}
		}

		// for each glob result, combine all the forms of the path
		var candidates []matchCandidate
		for _, result := range globResults {
			candidates = append(candidates, matchCandidate{
				fullpath:       result,
				relative:       strings.TrimPrefix(result, root),
				splitRemainder: afterSplit,
			})
		}

		return candidates
	}

	// setPlaceholders creates the placeholders for the matched file
	setPlaceholders := func(candidate matchCandidate, info fs.FileInfo) {
		repl.Set("http.matchers.file.relative", filepath.ToSlash(candidate.relative))
		repl.Set("http.matchers.file.absolute", filepath.ToSlash(candidate.fullpath))
		repl.Set("http.matchers.file.remainder", filepath.ToSlash(candidate.splitRemainder))

		fileType := "file"
		if info.IsDir() {
			fileType = "directory"
		}
		repl.Set("http.matchers.file.type", fileType)
	}

	// match file according to the configured policy
	switch m.TryPolicy {
	case "", tryPolicyFirstExist:
		for _, pattern := range m.TryFiles {
			if err := parseErrorCode(pattern); err != nil {
				caddyhttp.SetVar(r.Context(), caddyhttp.MatcherErrorVarKey, err)
				return
			}
			candidates := makeCandidates(pattern)
			for _, c := range candidates {
				if info, exists := m.strictFileExists(c.fullpath); exists {
					setPlaceholders(c, info)
					return true
				}
			}
		}

	case tryPolicyLargestSize:
		var largestSize int64
		var largest matchCandidate
		var largestInfo os.FileInfo
		for _, pattern := range m.TryFiles {
			candidates := makeCandidates(pattern)
			for _, c := range candidates {
				info, err := fs.Stat(m.fileSystem, c.fullpath)
				if err == nil && info.Size() > largestSize {
					largestSize = info.Size()
					largest = c
					largestInfo = info
				}
			}
		}
		if largestInfo == nil {
			return false
		}
		setPlaceholders(largest, largestInfo)
		return true

	case tryPolicySmallestSize:
		var smallestSize int64
		var smallest matchCandidate
		var smallestInfo os.FileInfo
		for _, pattern := range m.TryFiles {
			candidates := makeCandidates(pattern)
			for _, c := range candidates {
				info, err := fs.Stat(m.fileSystem, c.fullpath)
				if err == nil && (smallestSize == 0 || info.Size() < smallestSize) {
					smallestSize = info.Size()
					smallest = c
					smallestInfo = info
				}
			}
		}
		if smallestInfo == nil {
			return false
		}
		setPlaceholders(smallest, smallestInfo)
		return true

	case tryPolicyMostRecentlyMod:
		var recent matchCandidate
		var recentInfo os.FileInfo
		for _, pattern := range m.TryFiles {
			candidates := makeCandidates(pattern)
			for _, c := range candidates {
				info, err := fs.Stat(m.fileSystem, c.fullpath)
				if err == nil &&
					(recentInfo == nil || info.ModTime().After(recentInfo.ModTime())) {
					recent = c
					recentInfo = info
				}
			}
		}
		if recentInfo == nil {
			return false
		}
		setPlaceholders(recent, recentInfo)
		return true
	}

	return
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
func (m MatchFile) strictFileExists(file string) (os.FileInfo, bool) {
	info, err := fs.Stat(m.fileSystem, file)
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

// isCELMapLiteral returns whether the expression resolves to a map literal containing
// only string keys with or a placeholder call.
func isCELTryFilesLiteral(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_StructExpr:
		structExpr := e.GetStructExpr()
		if structExpr.GetMessageName() != "" {
			return false
		}
		for _, entry := range structExpr.GetEntries() {
			mapKey := entry.GetMapKey()
			mapVal := entry.GetValue()
			if !isCELStringLiteral(mapKey) {
				return false
			}
			mapKeyStr := mapKey.GetConstExpr().GetStringValue()
			if mapKeyStr == "try_files" || mapKeyStr == "split_path" {
				if !isCELStringListLiteral(mapVal) {
					return false
				}
			} else if mapKeyStr == "try_policy" || mapKeyStr == "root" {
				if !(isCELStringExpr(mapVal)) {
					return false
				}
			} else {
				return false
			}
		}
		return true
	}
	return false
}

// isCELStringExpr indicates whether the expression is a supported string expression
func isCELStringExpr(e *exprpb.Expr) bool {
	return isCELStringLiteral(e) || isCELCaddyPlaceholderCall(e) || isCELConcatCall(e)
}

// isCELStringLiteral returns whether the expression is a CEL string literal.
func isCELStringLiteral(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_ConstExpr:
		constant := e.GetConstExpr()
		switch constant.GetConstantKind().(type) {
		case *exprpb.Constant_StringValue:
			return true
		}
	}
	return false
}

// isCELCaddyPlaceholderCall returns whether the expression is a caddy placeholder call.
func isCELCaddyPlaceholderCall(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_CallExpr:
		call := e.GetCallExpr()
		if call.GetFunction() == "caddyPlaceholder" {
			return true
		}
	}
	return false
}

// isCELConcatCall tests whether the expression is a concat function (+) with string, placeholder, or
// other concat call arguments.
func isCELConcatCall(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_CallExpr:
		call := e.GetCallExpr()
		if call.GetTarget() != nil {
			return false
		}
		if call.GetFunction() != operators.Add {
			return false
		}
		for _, arg := range call.GetArgs() {
			if !isCELStringExpr(arg) {
				return false
			}
		}
		return true
	}
	return false
}

// isCELStringListLiteral returns whether the expression resolves to a list literal
// containing only string constants or a placeholder call.
func isCELStringListLiteral(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_ListExpr:
		list := e.GetListExpr()
		for _, elem := range list.GetElements() {
			if !isCELStringExpr(elem) {
				return false
			}
		}
		return true
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
)

const (
	tryPolicyFirstExist      = "first_exist"
	tryPolicyLargestSize     = "largest_size"
	tryPolicySmallestSize    = "smallest_size"
	tryPolicyMostRecentlyMod = "most_recently_modified"
)

// Interface guards
var (
	_ caddy.Validator              = (*MatchFile)(nil)
	_ caddyhttp.RequestMatcher     = (*MatchFile)(nil)
	_ caddyhttp.CELLibraryProducer = (*MatchFile)(nil)
)
