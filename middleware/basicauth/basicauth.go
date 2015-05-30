// Package basicauth implements HTTP Basic Authentication.
package basicauth

import (
	"crypto/subtle"
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// BasicAuth is middleware to protect resources with a username and password.
// Note that HTTP Basic Authentication is not secure by itself and should
// not be used to protect important assets without HTTPS. Even then, the
// security of HTTP Basic Auth is disputed. Use discretion when deciding
// what to protect with BasicAuth.
type BasicAuth struct {
	Next  middleware.Handler
	Rules []Rule
}

// ServeHTTP implements the middleware.Handler interface.
func (a BasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	var hasAuth bool
	var isAuthenticated bool

	for _, rule := range a.Rules {
		for _, res := range rule.Resources {
			if !middleware.Path(r.URL.Path).Matches(res) {
				continue
			}

			// Path matches; parse auth header
			username, password, ok := r.BasicAuth()
			hasAuth = true

			// Check credentials
			if !ok ||
				username != rule.Username ||
				subtle.ConstantTimeCompare([]byte(password), []byte(rule.Password)) != 1 {
				continue
			}

			// Flag set only on successful authentication
			isAuthenticated = true
		}
	}

	if hasAuth {
		if !isAuthenticated {
			w.Header().Set("WWW-Authenticate", "Basic")
			return http.StatusUnauthorized, nil
		}
		// "It's an older code, sir, but it checks out. I was about to clear them."
		return a.Next.ServeHTTP(w, r)
	}

	// Pass-thru when no paths match
	return a.Next.ServeHTTP(w, r)
}

// Rule represents a BasicAuth rule. A username and password
// combination protect the associated resources, which are
// file or directory paths.
type Rule struct {
	Username  string
	Password  string
	Resources []string
}
