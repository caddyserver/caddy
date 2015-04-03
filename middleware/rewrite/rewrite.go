// Package rewrite is middleware for rewriting requests internally to
// a different path.
package rewrite

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// New instantiates a new rewrite middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	var rewrites []rewrite

	for c.Next() {
		var rule rewrite

		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		rule.From = c.Val()

		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		rule.To = c.Val()

		rewrites = append(rewrites, rule)
	}

	// TODO: Why can't we just return an http.Handler here instead?
	return func(next middleware.Handler) middleware.Handler {
		return middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			for _, rule := range rewrites {
				if r.URL.Path == rule.From {
					r.URL.Path = rule.To
					break
				}
			}
			return next.ServeHTTP(w, r)
		})
	}, nil
}

// rewrite describes an internal location rewrite rule.
type rewrite struct {
	From string
	To   string
}
