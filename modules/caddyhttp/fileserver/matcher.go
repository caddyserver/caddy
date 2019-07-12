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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.matchers.file",
		New:  func() interface{} { return new(MatchFile) },
	})
}

// MatchFile is an HTTP request matcher that can match
// requests based upon file existence.
type MatchFile struct {
	// The root directory, used for creating absolute
	// file paths, and required when working with
	// relative paths; if not specified, the current
	// directory is assumed. Accepts placeholders.
	Root string `json:"root,omitempty"`

	// The list of files to try. Each path here is
	// considered relatice to Root. If nil, the
	// request URL's path will be assumed. Accepts
	// placeholders.
	TryFiles []string `json:"try_files,omitempty"`

	// How to choose a file in TryFiles.
	// Default is first_exist.
	TryPolicy string `json:"try_policy,omitempty"`
}

// Validate ensures m has a valid configuration.
func (m MatchFile) Validate() error {
	switch m.TryPolicy {
	case "",
		tryPolicyFirstExist,
		tryPolicyLargestSize,
		tryPolicySmallestSize,
		tryPolicyMostRecentMod:
	default:
		return fmt.Errorf("unknown try policy %s", m.TryPolicy)
	}
	return nil
}

// Match returns true if r matches m. Returns true
// if a file was matched. If so, two placeholders
// will be available:
//    - http.matchers.file.relative
//    - http.matchers.file.absolute
func (m MatchFile) Match(r *http.Request) bool {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)
	rel, abs, matched := m.selectFile(r)
	if matched {
		repl.Set("http.matchers.file.relative", rel)
		repl.Set("http.matchers.file.absolute", abs)
		return true
	}
	return false
}

// selectFile chooses a file according to m.TryPolicy by appending
// the paths in m.TryFiles to m.Root, with placeholder replacements.
// It returns the root-relative path to the matched file, the full
// or absolute path, and whether a match was made.
func (m MatchFile) selectFile(r *http.Request) (rel, abs string, matched bool) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)

	root := repl.ReplaceAll(m.Root, "")

	// if list of files to try was omitted entirely,
	// assume URL path
	if m.TryFiles == nil {
		// m is not a pointer, so this is safe
		m.TryFiles = []string{r.URL.Path}
	}

	switch m.TryPolicy {
	case "", tryPolicyFirstExist:
		for _, f := range m.TryFiles {
			suffix := repl.ReplaceAll(f, "")
			fullpath := sanitizedPathJoin(root, suffix)
			if fileExists(fullpath) {
				return suffix, fullpath, true
			}
		}

	case tryPolicyLargestSize:
		var largestSize int64
		var largestFilename string
		var largestSuffix string
		for _, f := range m.TryFiles {
			suffix := repl.ReplaceAll(f, "")
			fullpath := sanitizedPathJoin(root, suffix)
			info, err := os.Stat(fullpath)
			if err == nil && info.Size() > largestSize {
				largestSize = info.Size()
				largestFilename = fullpath
				largestSuffix = suffix
			}
		}
		return largestSuffix, largestFilename, true

	case tryPolicySmallestSize:
		var smallestSize int64
		var smallestFilename string
		var smallestSuffix string
		for _, f := range m.TryFiles {
			suffix := repl.ReplaceAll(f, "")
			fullpath := sanitizedPathJoin(root, suffix)
			info, err := os.Stat(fullpath)
			if err == nil && (smallestSize == 0 || info.Size() < smallestSize) {
				smallestSize = info.Size()
				smallestFilename = fullpath
				smallestSuffix = suffix
			}
		}
		return smallestSuffix, smallestFilename, true

	case tryPolicyMostRecentMod:
		var recentDate time.Time
		var recentFilename string
		var recentSuffix string
		for _, f := range m.TryFiles {
			suffix := repl.ReplaceAll(f, "")
			fullpath := sanitizedPathJoin(root, suffix)
			info, err := os.Stat(fullpath)
			if err == nil &&
				(recentDate.IsZero() || info.ModTime().After(recentDate)) {
				recentDate = info.ModTime()
				recentFilename = fullpath
				recentSuffix = suffix
			}
		}
		return recentSuffix, recentFilename, true
	}

	return
}

// fileExists returns true if file exists.
func fileExists(file string) bool {
	_, err := os.Stat(file)
	return !os.IsNotExist(err)
}

const (
	tryPolicyFirstExist    = "first_exist"
	tryPolicyLargestSize   = "largest_size"
	tryPolicySmallestSize  = "smallest_size"
	tryPolicyMostRecentMod = "most_recent_modified"
)

// Interface guards
var (
	_ caddy.Validator          = (*MatchFile)(nil)
	_ caddyhttp.RequestMatcher = (*MatchFile)(nil)
)
