// Package templates implements template execution for files to be dynamically rendered for the client.
package templates

import (
	"bytes"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"text/template"

	"github.com/mholt/caddy/middleware"
)

// ServeHTTP implements the middleware.Handler interface.
func (t Templates) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range t.Rules {
		if !middleware.Path(r.URL.Path).Matches(rule.Path) {
			continue
		}

		// Check for index files
		fpath := r.URL.Path
		if idx, ok := middleware.IndexFile(t.FileSys, fpath, rule.IndexFiles); ok {
			fpath = idx
		}

		// Check the extension
		reqExt := path.Ext(fpath)

		for _, ext := range rule.Extensions {
			if reqExt == ext {
				// Create execution context
				ctx := middleware.Context{Root: t.FileSys, Req: r, URL: r.URL}

				// Build the template
				tpl, err := template.ParseFiles(filepath.Join(t.Root, fpath))
				if err != nil {
					if os.IsNotExist(err) {
						return http.StatusNotFound, nil
					} else if os.IsPermission(err) {
						return http.StatusForbidden, nil
					}
					return http.StatusInternalServerError, err
				}

				// Execute it
				var buf bytes.Buffer
				err = tpl.Execute(&buf, ctx)
				if err != nil {
					return http.StatusInternalServerError, err
				}
				buf.WriteTo(w)

				return http.StatusOK, nil
			}
		}
	}

	return t.Next.ServeHTTP(w, r)
}

// Templates is middleware to render templated files as the HTTP response.
type Templates struct {
	Next    middleware.Handler
	Rules   []Rule
	Root    string
	FileSys http.FileSystem
}

// Rule represents a template rule. A template will only execute
// with this rule if the request path matches the Path specified
// and requests a resource with one of the extensions specified.
type Rule struct {
	Path       string
	Extensions []string
	IndexFiles []string
}
