// Package redirect is middleware for redirecting certain requests
// to other locations.
package redirect

import (
	"net/http"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Redirect is middleware to respond with HTTP redirects
type Redirect struct {
	Next  middleware.Handler
	Rules []Rule
}

// ServeHTTP implements the middleware.Handler interface.
func (rd Redirect) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range rd.Rules {
		if rule.From == "/" {
			// Catchall redirect preserves path (TODO: Standardize/formalize this behavior)
			http.Redirect(w, r, strings.TrimSuffix(rule.To, "/")+r.URL.Path, rule.Code)
			return 0, nil
		}
		if r.URL.Path == rule.From {
			http.Redirect(w, r, rule.To, rule.Code)
			return 0, nil
		}
	}
	return rd.Next.ServeHTTP(w, r)
}

// Rule describes an HTTP redirect rule.
type Rule struct {
	From, To string
	Code     int
}
