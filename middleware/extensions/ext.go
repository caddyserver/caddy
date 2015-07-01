// Package extensions contains middleware for clean URLs.
//
// The root path of the site is passed in as well as possible extensions
// to try internally for paths requested that don't match an existing
// resource. The first path+ext combination that matches a valid file
// will be used.
package extensions

import (
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Ext can assume an extension from clean URLs.
// It tries extensions in the order listed in Extensions.
type Ext struct {
	// Next handler in the chain
	Next middleware.Handler

	// Path to ther root of the site
	Root string

	// List of extensions to try
	Extensions []string
}

// ServeHTTP implements the middleware.Handler interface.
func (e Ext) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	urlpath := strings.TrimSuffix(r.URL.Path, "/")
	if path.Ext(urlpath) == "" && r.URL.Path[len(r.URL.Path)-1] != '/' {
		for _, ext := range e.Extensions {
			if resourceExists(e.Root, urlpath+ext) {
				r.URL.Path = urlpath + ext
				break
			}
		}
	}
	return e.Next.ServeHTTP(w, r)
}

// resourceExists returns true if the file specified at
// root + path exists; false otherwise.
func resourceExists(root, path string) bool {
	_, err := os.Stat(root + path)
	// technically we should use os.IsNotExist(err)
	// but we don't handle any other kinds of errors anyway
	return err == nil
}
