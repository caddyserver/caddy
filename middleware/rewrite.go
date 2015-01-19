package middleware

import "net/http"

// Rewrite is middleware for rewriting requests internally to
// a different path.
func Rewrite(p parser) Middleware {

	// Rewrite describes an internal location rewrite rule.
	type rewrite struct {
		From string
		To   string
	}

	var rewrites []rewrite

	for p.Next() {
		var rule rewrite

		if !p.NextArg() {
			return p.ArgErr()
		}
		rule.From = p.Val()

		if !p.NextArg() {
			return p.ArgErr()
		}
		rule.To = p.Val()

		rewrites = append(rewrites, rule)
	}

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
