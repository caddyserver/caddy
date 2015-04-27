// Package basicauth implements HTTP Basic Authentication.
package basicauth

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// New constructs a new BasicAuth middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {
	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	basic := BasicAuth{
		Rules: rules,
	}

	return func(next middleware.Handler) middleware.Handler {
		basic.Next = next
		return basic
	}, nil
}

// ServeHTTP implements the middleware.Handler interface.
func (a BasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range a.Rules {
		for _, res := range rule.Resources {
			if !middleware.Path(r.URL.Path).Matches(res) {
				continue
			}

			// Path matches; parse auth header
			username, password, ok := r.BasicAuth()

			// Check credentials
			if !ok || username != rule.Username || password != rule.Password {
				w.Header().Set("WWW-Authenticate", "Basic")
				return http.StatusUnauthorized, nil
			}

			// "It's an older code, sir, but it checks out. I was about to clear them."
			return a.Next.ServeHTTP(w, r)
		}
	}

	// Pass-thru when no paths match
	return a.Next.ServeHTTP(w, r)
}

func parse(c middleware.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		var rule Rule

		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			rule.Username = args[0]
			rule.Password = args[1]
			for c.NextBlock() {
				rule.Resources = append(rule.Resources, c.Val())
				if c.NextArg() {
					return rules, c.Err("Expecting only one resource per line (extra '" + c.Val() + "')")
				}
			}
		case 3:
			rule.Resources = append(rule.Resources, args[0])
			rule.Username = args[1]
			rule.Password = args[2]
		default:
			return rules, c.ArgErr()
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// BasicAuth is middleware to protect resources with a username and password.
// Note that HTTP Basic Authentication is not secure by itself and should
// not be used to protect important assets without HTTPS. Even then, the
// security of HTTP Basic Auth is disputed. Use discretion when deciding
// what to protect with BasicAuth.
type BasicAuth struct {
	Next  middleware.Handler
	Rules []Rule
}

// Rule represents a BasicAuth rule. A username and password
// combination protect the associated resources, which are
// file or directory paths.
type Rule struct {
	Username  string
	Password  string
	Resources []string
}
