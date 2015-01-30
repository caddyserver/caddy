// Package proxy is middleware that proxies requests.
package proxy

import (
	"log"
	"net/http"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// New creates a new instance of proxy middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	var rules []proxyRule

	for c.Next() {
		rule := proxyRule{}

		if !c.Args(&rule.from, &rule.to) {
			return nil, c.ArgErr()
		}

		rules = append(rules, rule)
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			for _, rule := range rules {
				if middleware.Path(r.URL.Path).Matches(rule.from) {
					client := &http.Client{}

					r.RequestURI = ""
					r.URL.Scheme = strings.ToLower(r.URL.Scheme)

					resp, err := client.Do(r)
					if err != nil {
						log.Fatal(err)
					}
					resp.Write(w)

				} else {
					next(w, r)
				}
			}
		}
	}, nil
}

type proxyRule struct {
	from string
	to   string
}
