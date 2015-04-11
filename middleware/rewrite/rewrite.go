// Package rewrite is middleware for rewriting requests internally to
// a different path.
package rewrite

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// New instantiates a new Rewrites middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	rewrites, err := parse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return Rewrite{Next: next, Rules: rewrites}
	}, nil
}

// Rewrite is middleware to rewrite request locations internally before being handled.
type Rewrite struct {
	Next  middleware.Handler
	Rules []RewriteRule
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

func parse(c middleware.Controller) ([]RewriteRule, error) {
	var rewrites []RewriteRule

	for c.Next() {
		var rule RewriteRule

		if !c.NextArg() {
			return rewrites, c.ArgErr()
		}
		rule.From = c.Val()

		if !c.NextArg() {
			return rewrites, c.ArgErr()
		}
		rule.To = c.Val()

		rewrites = append(rewrites, rule)
	}

	return rewrites, nil
}

// RewriteRule describes an internal location rewrite rule.
type RewriteRule struct {
	From, To string
}
