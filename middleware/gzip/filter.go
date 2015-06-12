package gzip

import (
	"net/http"
	"path"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Filter determines if a request should be gzipped.
type Filter interface {
	// ShouldCompress tells if gzip compression
	// should be done on the request.
	ShouldCompress(*http.Request) bool
}

// ExtFilter is Filter for file name extensions.
type ExtFilter struct {
	// Exts is the file name extensions to accept
	Exts Set
}

// extWildCard is the wildcard for extensions.
const extWildCard = "*"

// ShouldCompress checks if the request file extension matches any
// of the registered extensions. It returns true if the extension is
// found and false otherwise.
func (e ExtFilter) ShouldCompress(r *http.Request) bool {
	ext := path.Ext(r.URL.Path)
	return e.Exts.Contains(extWildCard) || e.Exts.Contains(ext)
}

// PathFilter is Filter for request path.
type PathFilter struct {
	// IgnoredPaths is the paths to ignore
	IgnoredPaths Set
}

// ShouldCompress checks if the request path matches any of the
// registered paths to ignore. It returns false if an ignored path
// is found and true otherwise.
func (p PathFilter) ShouldCompress(r *http.Request) bool {
	return !p.IgnoredPaths.ContainsFunc(func(value string) bool {
		return middleware.Path(r.URL.Path).Matches(value)
	})
}

// MIMEFilter is Filter for request content types.
type MIMEFilter struct {
	// Types is the MIME types to accept.
	Types Set
}

// defaultMIMETypes is the list of default MIME types to use.
var defaultMIMETypes = []string{
	"text/plain", "text/html", "text/css", "application/json", "application/javascript",
	"text/x-markdown", "text/xml", "application/xml",
}

// DefaultMIMEFilter creates a MIMEFilter with default types.
func DefaultMIMEFilter() MIMEFilter {
	m := MIMEFilter{Types: make(Set)}
	for _, mime := range defaultMIMETypes {
		m.Types.Add(mime)
	}
	return m
}

// ShouldCompress checks if the content type of the request
// matches any of the registered ones. It returns true if
// found and false otherwise.
func (m MIMEFilter) ShouldCompress(r *http.Request) bool {
	return m.Types.Contains(r.Header.Get("Content-Type"))
}

func ValidMIME(mime string) bool {
	s := strings.Split(mime, "/")
	return len(s) == 2 && strings.TrimSpace(s[0]) != "" && strings.TrimSpace(s[1]) != ""
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
	for k, _ := range s {
		if f(k) {
			return true
		}
	}
	return false
}
