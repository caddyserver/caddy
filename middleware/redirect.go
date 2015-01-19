package middleware

import "net/http"

// Redirect is middleware for redirecting certain requests
// to other locations.
func Redirect(p parser) Middleware {

	// Redirect describes an HTTP redirect rule.
	type redirect struct {
		From string
		To   string
		Code int
	}

	var redirects []redirect

	for p.Next() {
		var rule redirect

		// From
		if !p.NextArg() {
			return p.ArgErr()
		}
		rule.From = p.Val()

		// To
		if !p.NextArg() {
			return p.ArgErr()
		}
		rule.To = p.Val()

		// Status Code
		if !p.NextArg() {
			return p.ArgErr()
		}

		if code, ok := httpRedirs[p.Val()]; !ok {
			return p.Err("Parse", "Invalid redirect code '"+p.Val()+"'")
		} else {
			rule.Code = code
		}

		redirects = append(redirects, rule)
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for _, rule := range redirects {
				if r.URL.Path == rule.From {
					http.Redirect(w, r, rule.To, rule.Code)
					break
				}
			}
			next(w, r)
		}
	}
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
