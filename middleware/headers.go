package middleware

import (
	"net/http"
	"strings"

	"github.com/mholt/caddy/config"
)

// Headers is middleware that adds headers to the responses
// for requests matching a certain path.
func Headers(headers []config.Headers) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for _, rule := range headers {
				if pathsMatch(r.URL.Path, rule.Url) {
					for _, header := range rule.Headers {
						w.Header().Set(header.Name, header.Value)
					}
				}
			}
			next(w, r)
		}
	}
}

// Returns whether or not p1 and p2 are matching
// paths. This can be defined a number of ways
// and it is not for sure yet how to match URL/path
// strings. It may be a prefix match or a full
// string match, it may strip trailing slashes.
// Until the software hits 1.0, this will be in flux.
func pathsMatch(p1, p2 string) bool {
	return strings.HasPrefix(p1, p2)
}
