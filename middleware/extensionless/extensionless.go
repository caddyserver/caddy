// Package extensionless is middleware for clean URLs. A root path is
// passed in as well as possible extensions to add, internally,
// to paths requested. The first path+ext that matches a resource
// that exists will be used.
package extensionless

import (
	"net/http"
	"os"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// New creates a new instance of middleware that assumes extensions
// so the site can use cleaner, extensionless URLs
func New(c middleware.Controller) (middleware.Middleware, error) {
	root := c.Root()

	extensions, err := parse(c)
	if err != nil {
		return nil, err
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return Extensionless{
			Next:       next,
			Extensions: extensions,
			Root:       root,
		}.ServeHTTP
	}, nil
}

// Extensionless is an http.Handler that can assume an extension from clean URLs.
// It tries extensions in the order listed in Extensions.
type Extensionless struct {
	Next       http.HandlerFunc
	Extensions []string
	Root       string
}

// ServeHTTP implements the http.Handler interface.
func (e Extensionless) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !hasExt(r) {
		for _, ext := range e.Extensions {
			if resourceExists(e.Root, r.URL.Path+ext) {
				r.URL.Path = r.URL.Path + ext
				break
			}
		}
	}
	e.Next(w, r)
}

// parse sets up an instance of Extensionless middleware
// from a middleware controller and returns a list of extensions.
func parse(c middleware.Controller) ([]string, error) {
	var extensions []string

	for c.Next() {
		// At least one extension is required
		if !c.NextArg() {
			return extensions, c.ArgErr()
		}
		extensions = append(extensions, c.Val())

		// Tack on any other extensions that may have been listed
		for c.NextArg() {
			extensions = append(extensions, c.Val())
		}
	}

	return extensions, nil
}

// resourceExists returns true if the file specified at
// root + path exists; false otherwise.
func resourceExists(root, path string) bool {
	_, err := os.Stat(root + path)
	// technically we should use os.IsNotExist(err)
	// but we don't handle any other kinds of errors anyway
	return err == nil
}

// hasExt returns true if the HTTP request r has an extension,
// false otherwise.
func hasExt(r *http.Request) bool {
	if r.URL.Path[len(r.URL.Path)-1] == '/' {
		// directory
		return true
	}
	lastSep := strings.LastIndex(r.URL.Path, "/")
	lastDot := strings.LastIndex(r.URL.Path, ".")
	return lastDot > lastSep
}
