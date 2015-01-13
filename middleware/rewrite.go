package middleware

import (
	"net/http"

	"github.com/mholt/caddy/config"
)

// Rewrite is middleware for rewriting requests internally to
// a different path.
func Rewrite(rewrites []config.Rewrite) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for _, rule := range rewrites {
				if r.URL.Path == rule.From {
					r.URL.Path = rule.To
					break
				}
			}
			next(w, r)
		}
	}
}
