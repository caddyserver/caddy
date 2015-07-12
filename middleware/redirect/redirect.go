// Package redirect is middleware for redirecting certain requests
// to other locations.
package redirect

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"

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
		if rule.From == "/" {
			// Catchall redirect preserves path (TODO: Standardize/formalize this behavior)
			toURL, err := url.ParseRequestURI(rule.To)
			if err != nil {
				return 500, err
			}
			newPath := toURL.Host + toURL.Path + r.URL.Path
			rmSlashs := regexp.MustCompile("//+")
			newPath = rmSlashs.ReplaceAllString(newPath, "/")
			newPath = toURL.Scheme + "://" + newPath
			parameters := toURL.Query()
			for k, v := range r.URL.Query() {
				parameters.Set(k, v[0])
			}
			if len(parameters) > 0 {
				newPath = newPath + "?" + parameters.Encode()
			}
			if rule.Meta {
				fmt.Fprintf(w, metaRedir, html.EscapeString(newPath))
			} else {
				http.Redirect(w, r, newPath, rule.Code)
			}
			return 0, nil
		}
		if r.URL.Path == rule.From {
			if rule.Meta {
				fmt.Fprintf(w, metaRedir, html.EscapeString(rule.To))
			} else {
				http.Redirect(w, r, rule.To, rule.Code)
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

var metaRedir = `<html>
<head>
  <meta http-equiv="refresh" content="0;URL='%s'">
</head>
<body>redirecting...</body>
</html>`
