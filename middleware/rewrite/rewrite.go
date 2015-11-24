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

	"github.com/mholt/caddy/middleware"
)

// Rewrite is middleware to rewrite request locations internally before being handled.
type Rewrite struct {
	Next  middleware.Handler
	Rules []Rule
}

// ServeHTTP implements the middleware.Handler interface.
func (rw Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range rw.Rules {
		if ok := rule.Rewrite(r); ok {
			break
		}
	}
	return rw.Next.ServeHTTP(w, r)
}

// Rule describes an internal location rewrite rule.
type Rule interface {
	// Rewrite rewrites the internal location of the current request.
	Rewrite(*http.Request) bool
}

// SimpleRule is a simple rewrite rule.
type SimpleRule struct {
	From, To string
}

// NewSimpleRule creates a new Simple Rule
func NewSimpleRule(from, to string) SimpleRule {
	return SimpleRule{from, to}
}

// Rewrite rewrites the internal location of the current request.
func (s SimpleRule) Rewrite(r *http.Request) bool {
	if s.From == r.URL.Path {
		// take note of this rewrite for internal use by fastcgi
		// all we need is the URI, not full URL
		r.Header.Set(headerFieldName, r.URL.RequestURI())

		// replace variables
		to := path.Clean(middleware.NewReplacer(r, nil, "").Replace(s.To))

		r.URL.Path = to
		return true
	}
	return false
}

// RegexpRule is a rewrite rule based on a regular expression
type RegexpRule struct {
	// Path base. Request to this path and subpaths will be rewritten
	Base string

	// Path to rewrite to
	To string

	// Extensions to filter by
	Exts []string

	*regexp.Regexp
}

// NewRegexpRule creates a new RegexpRule. It returns an error if regexp
// pattern (pattern) or extensions (ext) are invalid.
func NewRegexpRule(base, pattern, to string, ext []string) (*RegexpRule, error) {
	r, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// validate extensions
	for _, v := range ext {
		if len(v) < 2 || (len(v) < 3 && v[0] == '!') {
			// check if no extension is specified
			if v != "/" && v != "!/" {
				return nil, fmt.Errorf("invalid extension %v", v)
			}
		}
	}

	return &RegexpRule{
		base,
		to,
		ext,
		r,
	}, nil
}

// Rewrite rewrites the internal location of the current request.
func (r *RegexpRule) Rewrite(req *http.Request) bool {
	rPath := req.URL.Path

	// validate base
	if !middleware.Path(rPath).Matches(r.Base) {
		return false
	}

	// validate extensions
	if !r.matchExt(rPath) {
		return false
	}

	// include trailing slash in regexp if present
	start := len(r.Base)
	if strings.HasSuffix(r.Base, "/") {
		start--
	}

	// validate regexp
	if !r.MatchString(rPath[start:]) {
		return false
	}

	// replace variables
	to := path.Clean(middleware.NewReplacer(req, nil, "").Replace(r.To))

	// validate resulting path
	url, err := url.Parse(to)
	if err != nil {
		return false
	}

	// take note of this rewrite for internal use by fastcgi
	// all we need is the URI, not full URL
	req.Header.Set(headerFieldName, req.URL.RequestURI())

	// perform rewrite
	req.URL.Path = url.Path
	if url.RawQuery != "" {
		// overwrite query string if present
		req.URL.RawQuery = url.RawQuery
	}
	return true
}

// matchExt matches rPath against registered file extensions.
// Returns true if a match is found and false otherwise.
func (r *RegexpRule) matchExt(rPath string) bool {
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

	if mustUse {
		return false
	}
	return true
}

// When a rewrite is performed, this header is added to the request
// and is for internal use only, specifically the fastcgi middleware.
// It contains the original request URI before the rewrite.
const headerFieldName = "Caddy-Rewrite-Original-URI"
