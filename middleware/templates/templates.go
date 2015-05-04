// Package templates implements template execution for files to be dynamically rendered for the client.
package templates

import (
	"bytes"
	"net/http"
	"path"
	"text/template"

	"github.com/mholt/caddy/middleware"
)

// ServeHTTP implements the middleware.Handler interface.
func (t Templates) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range t.Rules {
		if !middleware.Path(r.URL.Path).Matches(rule.Path) {
			continue
		}

		reqExt := path.Ext(r.URL.Path)

		for _, ext := range rule.Extensions {
			if reqExt == ext {
				// Create execution context
				ctx := context{root: http.Dir(t.Root), req: r, URL: r.URL}

				// Build the template
				tpl, err := template.ParseFiles(t.Root + r.URL.Path)
				if err != nil {
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
	Next  middleware.Handler
	Root  string
	Rules []Rule
}

// Rule represents a template rule. A template will only execute
// with this rule if the request path matches the Path specified
// and requests a resource with one of the extensions specified.
type Rule struct {
	Path       string
	Extensions []string
}
