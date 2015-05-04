// Package rewrite is middleware for rewriting requests internally to
// a different path.
package rewrite

import (
	"net/http"

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
		if r.URL.Path == rule.From {
			r.URL.Path = rule.To
			break
		}
	}
	return rw.Next.ServeHTTP(w, r)
}

// A Rule describes an internal location rewrite rule.
type Rule struct {
	From, To string
}
