// Package proxy is middleware that proxies requests.
package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

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
					var scheme string
					if r.TLS == nil {
						scheme = "http"
					} else {
						scheme = "https"
					}

					baseUrl, err := url.Parse(scheme + "://" + rule.to)
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
