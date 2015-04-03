// Package redirect is middleware for redirecting certain requests
// to other locations.
package redirect

import (
	"net/http"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// New creates a new redirect middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	var redirects []Redirect

	for c.Next() {
		var rule Redirect
		args := c.RemainingArgs()

		if len(args) == 1 {
			// Only 'To' specified
			rule.From = "/"
			rule.To = c.Val()
			rule.Code = 307 // TODO: Consider 301 instead?
			redirects = append(redirects, rule)
		} else if len(args) == 3 {
			// From, To, and Code specified
			rule.From = args[0]
			rule.To = args[1]
			if code, ok := httpRedirs[args[2]]; !ok {
				return nil, c.Err("Invalid redirect code '" + c.Val() + "'")
			} else {
				rule.Code = code
			}
			redirects = append(redirects, rule)
		} else {
			return nil, c.ArgErr()
		}
	}

	return func(next middleware.Handler) middleware.Handler {
		return middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			for _, rule := range redirects {
				if middleware.Path(r.URL.Path).Matches(rule.From) {
					if rule.From == "/" {
						// Catchall redirect preserves path (TODO: This should be made more consistent...)
						http.Redirect(w, r, strings.TrimSuffix(rule.To, "/")+r.URL.Path, rule.Code)
						return 0, nil
					}
					http.Redirect(w, r, rule.To, rule.Code)
					return 0, nil
				}
			}
			return next.ServeHTTP(w, r)
		})
	}, nil
}

// redirect describes an HTTP redirect rule.
type Redirect struct {
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
