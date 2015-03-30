// Package redirect is middleware for redirecting certain requests
// to other locations.
package redirect

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// New creates a new redirect middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	var redirects []redirect

	for c.Next() {
		var rule redirect

		// From
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		rule.From = c.Val()

		// To
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		rule.To = c.Val()

		// Status Code
		if !c.NextArg() {
			return nil, c.ArgErr()
		}

		if code, ok := httpRedirs[c.Val()]; !ok {
			return nil, c.Err("Invalid redirect code '" + c.Val() + "'")
		} else {
			rule.Code = code
		}

		redirects = append(redirects, rule)
	}

	return func(next middleware.HandlerFunc) middleware.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) (int, error) {
			for _, rule := range redirects {
				if r.URL.Path == rule.From {
					http.Redirect(w, r, rule.To, rule.Code)
					return 0, nil
				}
			}
			return next(w, r)
		}
	}, nil
}

// redirect describes an HTTP redirect rule.
type redirect struct {
	From string
	To   string
	Code int
}

// httpRedirs is a list of supported HTTP redirect codes.
var httpRedirs = map[string]int{
	"300": 300,
	"301": 301,
	"302": 302,
	"303": 303,
	"304": 304,
	"305": 305,
	"306": 306,
	"307": 307,
	"308": 308,
}
