// Package rewrite is middleware for rewriting requests internally to
// a different path.
package rewrite

import (
	"net/http"

	"fmt"
	"github.com/mholt/caddy/middleware"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
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

// A Rule describes an internal location rewrite rule.
type Rule interface {
	Rewrite(*http.Request) bool
}

type SimpleRule [2]string

func NewSimpleRule(from, to string) SimpleRule {
	return SimpleRule{from, to}
}

func (s SimpleRule) Rewrite(r *http.Request) bool {
	if s[0] == r.URL.Path {
		r.URL.Path = s[1]
		return true
	}
	return false
}

type RegexpRule struct {
	base, to string
	ext      []string
	*regexp.Regexp
}

func NewRegexpRule(base, pattern, to string, ext []string) (*RegexpRule, error) {
	r, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// validate extensions
	for _, v := range ext {
		if len(v) < 2 || (len(v) < 3 && v[0] == '!') {
			// check if it is no extension
			if v != "/" && v != "!/" {
				return nil, fmt.Errorf("Invalid extension %v", v)
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

var regexpVars [2]string = [2]string{
	"$path",
	"$query",
}

func (r *RegexpRule) Rewrite(req *http.Request) bool {
	rPath := req.URL.Path
	if strings.Index(rPath, r.base) != 0 {
		return false
	}
	if !r.matchExt(rPath) {
		return false
	}
	if !r.MatchString(req.URL.Path) {
		return false
	}

	to := r.to

	// check variables
	for _, v := range regexpVars {
		if strings.Contains(r.to, v) {
			switch v {
			case regexpVars[0]:
				to = strings.Replace(to, v, req.URL.Path[1:], -1)
			case regexpVars[1]:
				to = strings.Replace(to, v, req.URL.RawQuery, -1)
			}
		}
	}

	url, err := url.Parse(to)
	if err != nil {
		return false
	}

	req.URL.Path = url.Path
	req.URL.RawQuery = url.RawQuery

	return true
}

func (r *RegexpRule) matchExt(rPath string) bool {
	f := filepath.Base(rPath)
	ext := path.Ext(f)
	if ext == "" {
		ext = "/"
	}
	mustUse := false
	for _, v := range r.ext {
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
