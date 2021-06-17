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
	"net/http"
	"os"
	"path"
	"strings"
	"time"

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
type MatchFile struct {
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
	// be no trailing slash. Accepts placeholders.
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
//     file <files...> {
//         root <path>
//         try_files <files...>
//         try_policy first_exist|smallest_size|largest_size|most_recently_modified
//     }
//
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

// Provision sets up m's defaults.
func (m *MatchFile) Provision(_ caddy.Context) error {
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
//    - http.matchers.file.relative
//    - http.matchers.file.absolute
//    - http.matchers.file.type
//    - http.matchers.file.remainder
func (m MatchFile) Match(r *http.Request) bool {
	return m.selectFile(r)
}

// selectFile chooses a file according to m.TryPolicy by appending
// the paths in m.TryFiles to m.Root, with placeholder replacements.
func (m MatchFile) selectFile(r *http.Request) (matched bool) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	root := repl.ReplaceAll(m.Root, ".")

	// common preparation of the file into parts
	prepareFilePath := func(file string) (suffix, fullpath, remainder string) {
		suffix, remainder = m.firstSplit(path.Clean(repl.ReplaceAll(file, "")))
		if strings.HasSuffix(file, "/") {
			suffix += "/"
		}
		fullpath = caddyhttp.SanitizedPathJoin(root, suffix)
		return
	}

	// sets up the placeholders for the matched file
	setPlaceholders := func(info os.FileInfo, rel string, abs string, remainder string) {
		repl.Set("http.matchers.file.relative", rel)
		repl.Set("http.matchers.file.absolute", abs)
		repl.Set("http.matchers.file.remainder", remainder)

		fileType := "file"
		if info.IsDir() {
			fileType = "directory"
		}
		repl.Set("http.matchers.file.type", fileType)
	}

	switch m.TryPolicy {
	case "", tryPolicyFirstExist:
		for _, f := range m.TryFiles {
			suffix, fullpath, remainder := prepareFilePath(f)
			if info, exists := strictFileExists(fullpath); exists {
				setPlaceholders(info, suffix, fullpath, remainder)
				return true
			}
		}

	case tryPolicyLargestSize:
		var largestSize int64
		var largestFilename string
		var largestSuffix string
		var remainder string
		var info os.FileInfo
		for _, f := range m.TryFiles {
			suffix, fullpath, splitRemainder := prepareFilePath(f)
			info, err := os.Stat(fullpath)
			if err == nil && info.Size() > largestSize {
				largestSize = info.Size()
				largestFilename = fullpath
				largestSuffix = suffix
				remainder = splitRemainder
			}
		}
		setPlaceholders(info, largestSuffix, largestFilename, remainder)
		return true

	case tryPolicySmallestSize:
		var smallestSize int64
		var smallestFilename string
		var smallestSuffix string
		var remainder string
		var info os.FileInfo
		for _, f := range m.TryFiles {
			suffix, fullpath, splitRemainder := prepareFilePath(f)
			info, err := os.Stat(fullpath)
			if err == nil && (smallestSize == 0 || info.Size() < smallestSize) {
				smallestSize = info.Size()
				smallestFilename = fullpath
				smallestSuffix = suffix
				remainder = splitRemainder
			}
		}
		setPlaceholders(info, smallestSuffix, smallestFilename, remainder)
		return true

	case tryPolicyMostRecentlyMod:
		var recentDate time.Time
		var recentFilename string
		var recentSuffix string
		var remainder string
		var info os.FileInfo
		for _, f := range m.TryFiles {
			suffix, fullpath, splitRemainder := prepareFilePath(f)
			info, err := os.Stat(fullpath)
			if err == nil &&
				(recentDate.IsZero() || info.ModTime().After(recentDate)) {
				recentDate = info.ModTime()
				recentFilename = fullpath
				recentSuffix = suffix
				remainder = splitRemainder
			}
		}
		setPlaceholders(info, recentSuffix, recentFilename, remainder)
		return true
	}

	return
}

// strictFileExists returns true if file exists
// and matches the convention of the given file
// path. If the path ends in a forward slash,
// the file must also be a directory; if it does
// NOT end in a forward slash, the file must NOT
// be a directory.
func strictFileExists(file string) (os.FileInfo, bool) {
	stat, err := os.Stat(file)
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
		return stat, stat.IsDir()
	}
	// by convention, file paths NOT ending
	// in a path separator must NOT be a directory
	return stat, !stat.IsDir()
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

const (
	tryPolicyFirstExist      = "first_exist"
	tryPolicyLargestSize     = "largest_size"
	tryPolicySmallestSize    = "smallest_size"
	tryPolicyMostRecentlyMod = "most_recently_modified"
)

// Interface guards
var (
	_ caddy.Validator          = (*MatchFile)(nil)
	_ caddyhttp.RequestMatcher = (*MatchFile)(nil)
)
