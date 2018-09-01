// Copyright 2015 Light Code Labs, LLC
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

package gzip

import (
	"net/http"
	"path"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// RequestFilter determines if a request should be gzipped.
type RequestFilter interface {
	// ShouldCompress tells if gzip compression
	// should be done on the request.
	ShouldCompress(*http.Request) bool
}

// defaultExtensions is the list of default extensions for which to enable gzipping.
var defaultExtensions = []string{"", ".txt", ".htm", ".html", ".css", ".php", ".js", ".json",
	".md", ".mdown", ".xml", ".svg", ".go", ".cgi", ".py", ".pl", ".aspx", ".asp", ".m3u", ".m3u8"}

// DefaultExtFilter creates an ExtFilter with default extensions.
func DefaultExtFilter() ExtFilter {
	m := ExtFilter{Exts: make(Set)}
	for _, extension := range defaultExtensions {
		m.Exts.Add(extension)
	}
	return m
}

// ExtFilter is RequestFilter for file name extensions.
type ExtFilter struct {
	// Exts is the file name extensions to accept
	Exts Set
}

// ExtWildCard is the wildcard for extensions.
const ExtWildCard = "*"

// ShouldCompress checks if the request file extension matches any
// of the registered extensions. It returns true if the extension is
// found and false otherwise.
func (e ExtFilter) ShouldCompress(r *http.Request) bool {
	ext := path.Ext(r.URL.Path)
	return e.Exts.Contains(ExtWildCard) || e.Exts.Contains(ext)
}

// PathFilter is RequestFilter for request path.
type PathFilter struct {
	// IgnoredPaths is the paths to ignore
	IgnoredPaths Set
}

// ShouldCompress checks if the request path matches any of the
// registered paths to ignore. It returns false if an ignored path
// is found and true otherwise.
func (p PathFilter) ShouldCompress(r *http.Request) bool {
	return !p.IgnoredPaths.ContainsFunc(func(value string) bool {
		return httpserver.Path(r.URL.Path).Matches(value)
	})
}

// Set stores distinct strings.
type Set map[string]struct{}

// Add adds an element to the set.
func (s Set) Add(value string) {
	s[value] = struct{}{}
}

// Remove removes an element from the set.
func (s Set) Remove(value string) {
	delete(s, value)
}

// Contains check if the set contains value.
func (s Set) Contains(value string) bool {
	_, ok := s[value]
	return ok
}

// ContainsFunc is similar to Contains. It iterates all the
// elements in the set and passes each to f. It returns true
// on the first call to f that returns true and false otherwise.
func (s Set) ContainsFunc(f func(string) bool) bool {
	for k := range s {
		if f(k) {
			return true
		}
	}
	return false
}
