// Package rewrite is middleware for rewriting requests internally to
// a different path.
package rewrite

import (
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Result is the result of a rewrite
type Result int

const (
	// RewriteIgnored is returned when rewrite is not done on request.
	RewriteIgnored Result = iota
	// RewriteDone is returned when rewrite is done on request.
	RewriteDone
	// RewriteStatus is returned when rewrite is not needed and status code should be set
	// for the request.
	RewriteStatus
)

// Rewrite is middleware to rewrite request locations internally before being handled.
type Rewrite struct {
	Next    middleware.Handler
	FileSys http.FileSystem
	Rules   []Rule
}

// ServeHTTP implements the middleware.Handler interface.
func (rw Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
outer:
	for _, rule := range rw.Rules {
		switch result := rule.Rewrite(rw.FileSys, r); result {
		case RewriteDone:
			break outer
		case RewriteIgnored:
			break
		case RewriteStatus:
			// only valid for complex rules.
			if cRule, ok := rule.(*ComplexRule); ok && cRule.Status != 0 {
				return cRule.Status, nil
			}
		}
	}
	return rw.Next.ServeHTTP(w, r)
}

// Rule describes an internal location rewrite rule.
type Rule interface {
	// Rewrite rewrites the internal location of the current request.
	Rewrite(http.FileSystem, *http.Request) Result
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
func (s SimpleRule) Rewrite(fs http.FileSystem, r *http.Request) Result {
	if s.From == r.URL.Path {
		// take note of this rewrite for internal use by fastcgi
		// all we need is the URI, not full URL
		r.Header.Set(headerFieldName, r.URL.RequestURI())

		// attempt rewrite
		return To(fs, r, s.To, newReplacer(r))
	}
	return RewriteIgnored
}

// ComplexRule is a rewrite rule based on a regular expression
type ComplexRule struct {
	// Path base. Request to this path and subpaths will be rewritten
	Base string

	// Path to rewrite to
	To string

	// If set, neither performs rewrite nor proceeds
	// with request. Only returns code.
	Status int

	// Extensions to filter by
	Exts []string

	// Rewrite conditions
	Ifs []If

	*regexp.Regexp
}

// NewComplexRule creates a new RegexpRule. It returns an error if regexp
// pattern (pattern) or extensions (ext) are invalid.
func NewComplexRule(base, pattern, to string, status int, ext []string, ifs []If) (*ComplexRule, error) {
	// validate regexp if present
	var r *regexp.Regexp
	if pattern != "" {
		var err error
		r, err = regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
	}

	// validate extensions if present
	for _, v := range ext {
		if len(v) < 2 || (len(v) < 3 && v[0] == '!') {
			// check if no extension is specified
			if v != "/" && v != "!/" {
				return nil, fmt.Errorf("invalid extension %v", v)
			}
		}
	}

	return &ComplexRule{
		Base:   base,
		To:     to,
		Status: status,
		Exts:   ext,
		Ifs:    ifs,
		Regexp: r,
	}, nil
}

// Rewrite rewrites the internal location of the current request.
func (r *ComplexRule) Rewrite(fs http.FileSystem, req *http.Request) (re Result) {
	rPath := req.URL.Path
	replacer := newReplacer(req)

	// validate base
	if !middleware.Path(rPath).Matches(r.Base) {
		return
	}

	// validate extensions
	if !r.matchExt(rPath) {
		return
	}

	// validate regexp if present
	if r.Regexp != nil {
		// include trailing slash in regexp if present
		start := len(r.Base)
		if strings.HasSuffix(r.Base, "/") {
			start--
		}

		matches := r.FindStringSubmatch(rPath[start:])
		switch len(matches) {
		case 0:
			// no match
			return
		default:
			// set regexp match variables {1}, {2} ...
			for i := 1; i < len(matches); i++ {
				replacer.Set(fmt.Sprint(i), matches[i])
			}
		}
	}

	// validate rewrite conditions
	for _, i := range r.Ifs {
		if !i.True(req) {
			return
		}
	}

	// if status is present, stop rewrite and return it.
	if r.Status != 0 {
		return RewriteStatus
	}

	// attempt rewrite
	return To(fs, req, r.To, replacer)
}

// matchExt matches rPath against registered file extensions.
// Returns true if a match is found and false otherwise.
func (r *ComplexRule) matchExt(rPath string) bool {
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
