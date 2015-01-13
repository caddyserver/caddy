package middleware

import (
	"net/http"

	"github.com/mholt/caddy/config"
)

// Redirect is middleware for redirecting certain requests
// to other locations.
func Redirect(redirs []config.Redirect) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for _, rule := range redirs {
				if r.URL.Path == rule.From {
					http.Redirect(w, r, rule.To, rule.Code)
					break
				}
			}
			next(w, r)
		}
	}
}
