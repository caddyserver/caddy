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

// Package rewrite is middleware for rewriting requests internally to
// a different path.
package rewrite

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Result is the result of a rewrite
type Result int

const (
	// RewriteIgnored is returned when rewrite is not done on request.
	RewriteIgnored Result = iota
	// RewriteDone is returned when rewrite is done on request.
	RewriteDone
)

// Rewrite is middleware to rewrite request locations internally before being handled.
type Rewrite struct {
	Next    httpserver.Handler
	FileSys http.FileSystem
	Rules   []httpserver.HandlerConfig
}

// ServeHTTP implements the httpserver.Handler interface.
func (rw Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if rule := httpserver.ConfigSelector(rw.Rules).Select(r); rule != nil {
		rule.(Rule).Rewrite(rw.FileSys, r)
	}

	return rw.Next.ServeHTTP(w, r)
}

// Rule describes an internal location rewrite rule.
type Rule interface {
	httpserver.HandlerConfig
	// Rewrite rewrites the internal location of the current request.
	Rewrite(http.FileSystem, *http.Request) Result
}

// SimpleRule is a simple rewrite rule.
type SimpleRule struct {
	Regexp *regexp.Regexp
	To     string
	Negate bool
}

// NewSimpleRule creates a new Simple Rule
func NewSimpleRule(from, to string, negate bool) (*SimpleRule, error) {
	r, err := regexp.Compile(from)
	if err != nil {
		return nil, err
	}
	return &SimpleRule{
		Regexp: r,
		To:     to,
		Negate: negate,
	}, nil
}

// BasePath satisfies httpserver.Config
func (s SimpleRule) BasePath() string { return "/" }

// Match satisfies httpserver.Config
func (s *SimpleRule) Match(r *http.Request) bool {
	matches := regexpMatches(s.Regexp, "/", r.URL.Path)
	if s.Negate {
		return len(matches) == 0
	}
	return len(matches) > 0
}

// Rewrite rewrites the internal location of the current request.
func (s *SimpleRule) Rewrite(fs http.FileSystem, r *http.Request) Result {

	// attempt rewrite
	return To(fs, r, s.To, newReplacer(r))
}

// ComplexRule is a rewrite rule based on a regular expression
type ComplexRule struct {
	// Path base. Request to this path and subpaths will be rewritten
	Base string

	// Path to rewrite to
	To string

	// Extensions to filter by
	Exts []string

	// Request matcher
	httpserver.RequestMatcher

	Regexp *regexp.Regexp
}

// NewComplexRule creates a new RegexpRule. It returns an error if regexp
// pattern (pattern) or extensions (ext) are invalid.
func NewComplexRule(base, pattern, to string, ext []string, matcher httpserver.RequestMatcher) (ComplexRule, error) {
	// validate regexp if present
	var r *regexp.Regexp
	if pattern != "" {
		var err error
		r, err = regexp.Compile(pattern)
		if err != nil {
			return ComplexRule{}, err
		}
	}

	// validate extensions if present
	for _, v := range ext {
		if len(v) < 2 || (len(v) < 3 && v[0] == '!') {
			// check if no extension is specified
			if v != "/" && v != "!/" {
				return ComplexRule{}, fmt.Errorf("invalid extension %v", v)
			}
		}
	}

	// use both IfMatcher and PathMatcher
	matcher = httpserver.MergeRequestMatchers(
		// If condition matcher
		matcher,
		// Base path matcher
		httpserver.PathMatcher(base),
	)

	return ComplexRule{
		Base:           base,
		To:             to,
		Exts:           ext,
		RequestMatcher: matcher,
		Regexp:         r,
	}, nil
}

// BasePath satisfies httpserver.Config
func (r ComplexRule) BasePath() string { return r.Base }

// Match satisfies httpserver.Config.
//
// Though ComplexRule embeds a RequestMatcher, additional
// checks are needed which requires a custom implementation.
func (r ComplexRule) Match(req *http.Request) bool {
	// validate RequestMatcher
	// includes if and path
	if !r.RequestMatcher.Match(req) {
		return false
	}

	// validate extensions
	if !r.matchExt(req.URL.Path) {
		return false
	}

	// if regex is nil, ignore
	if r.Regexp == nil {
		return true
	}
	// otherwise validate regex
	return regexpMatches(r.Regexp, r.Base, req.URL.Path) != nil
}

// Rewrite rewrites the internal location of the current request.
func (r ComplexRule) Rewrite(fs http.FileSystem, req *http.Request) (re Result) {
	replacer := newReplacer(req)

	// validate regexp if present
	if r.Regexp != nil {
		matches := regexpMatches(r.Regexp, r.Base, req.URL.Path)
		switch len(matches) {
		case 0:
			// no match
			return
		default:
			// set regexp match variables {1}, {2} ...

			// url escaped values of ? and #.
			q, f := url.QueryEscape("?"), url.QueryEscape("#")

			for i := 1; i < len(matches); i++ {
				// Special case of unescaped # and ? by stdlib regexp.
				// Reverse the unescape.
				if strings.ContainsAny(matches[i], "?#") {
					matches[i] = strings.NewReplacer("?", q, "#", f).Replace(matches[i])
				}

				replacer.Set(fmt.Sprint(i), matches[i])
			}
		}
	}

	// attempt rewrite
	return To(fs, req, r.To, replacer)
}

// matchExt matches rPath against registered file extensions.
// Returns true if a match is found and false otherwise.
func (r ComplexRule) matchExt(rPath string) bool {
	f := filepath.Base(rPath)
	ext := path.Ext(f)
	if ext == "" {
		ext = "/"
	}

	mustUse := false
	for _, v := range r.Exts {
		use := true
		if v[0] == '!' {
			use = false
			v = v[1:]
		}

		if use {
			mustUse = true
		}

		if ext == v {
			return use
		}
	}

	return !mustUse
}

func regexpMatches(regexp *regexp.Regexp, base, rPath string) []string {
	if regexp != nil {
		// include trailing slash in regexp if present
		start := len(base)
		if strings.HasSuffix(base, "/") {
			start--
		}
		return regexp.FindStringSubmatch(rPath[start:])
	}
	return nil
}

func newReplacer(r *http.Request) httpserver.Replacer {
	return httpserver.NewReplacer(r, nil, "")
}
