// Package redirect is middleware for redirecting certain requests
// to other locations.
package redirect

import (
	"fmt"
	"html"
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// Redirect is middleware to respond with HTTP redirects
type Redirect struct {
	Next  middleware.Handler
	Rules []Rule
}

// ServeHTTP implements the middleware.Handler interface.
func (rd Redirect) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range rd.Rules {
		if rule.From == "/" || r.URL.Path == rule.From {
			to := middleware.NewReplacer(r, nil, "").Replace(rule.To)
			if rule.Meta {
				safeTo := html.EscapeString(to)
				fmt.Fprintf(w, metaRedir, safeTo, safeTo)
			} else {
				http.Redirect(w, r, to, rule.Code)
			}
			return 0, nil
		}
	}
	return rd.Next.ServeHTTP(w, r)
}

// Rule describes an HTTP redirect rule.
type Rule struct {
	From, To string
	Code     int
	Meta     bool
}

// Script tag comes first since that will better imitate a redirect in the browser's
// history, but the meta tag is a fallback for most non-JS clients.
const metaRedir = `<!DOCTYPE html>
<html>
	<head>
		<script>window.location.replace("%s");</script>
		<meta http-equiv="refresh" content="0; URL='%s'">
	</head>
	<body>Redirecting...</body>
</html>`
