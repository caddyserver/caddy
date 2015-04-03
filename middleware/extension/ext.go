// Package extension is middleware for clean URLs. The root path
// of the site is passed in as well as possible extensions to try
// internally for paths requested that don't match an existing
// resource. The first path+ext combination that matches a valid
// file will be used.
package extension

import (
	"net/http"
	"os"
	"path"
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

	return func(next middleware.HandlerFunc) middleware.HandlerFunc {
		return Ext{
			Next:       next,
			Extensions: extensions,
			Root:       root,
		}.ServeHTTP
	}, nil
}

// Ext can assume an extension from clean URLs.
// It tries extensions in the order listed in Extensions.
type Ext struct {
	// Next handler in the chain
	Next middleware.HandlerFunc

	// Path to ther root of the site
	Root string

	// List of extensions to try
	Extensions []string
}

// ServeHTTP implements the middleware.Handler interface.
func (e Ext) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	urlpath := strings.TrimSuffix(r.URL.Path, "/")
	if path.Ext(urlpath) == "" {
		for _, ext := range e.Extensions {
			if resourceExists(e.Root, urlpath+ext) {
				r.URL.Path = urlpath + ext
				break
			}
		}
	}
	return e.Next(w, r)
}

// parse sets up an instance of extension middleware
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
		extensions = append(extensions, c.RemainingArgs()...)
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
