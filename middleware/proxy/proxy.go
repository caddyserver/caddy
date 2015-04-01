// Package proxy is middleware that proxies requests.
package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
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

	return func(next middleware.HandlerFunc) middleware.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) (int, error) {

			for _, rule := range rules {
				if middleware.Path(r.URL.Path).Matches(rule.from) {
					var base string

					if strings.HasPrefix(rule.to, "http") { // includes https
						// destination includes a scheme! no need to guess
						base = rule.to
					} else {
						// no scheme specified; assume same as request
						var scheme string
						if r.TLS == nil {
							scheme = "http"
						} else {
							scheme = "https"
						}
						base = scheme + "://" + rule.to
					}

					baseUrl, err := url.Parse(base)
					if err != nil {
						log.Fatal(err)
					}
					r.Host = baseUrl.Host

					// TODO: Construct this before; not during every request, if possible
					proxy := httputil.NewSingleHostReverseProxy(baseUrl)
					proxy.ServeHTTP(w, r)
					return 0, nil
				}
			}

			return next(w, r)
		}
	}, nil
}

type proxyRule struct {
	from string
	to   string
}
