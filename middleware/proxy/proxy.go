// Package proxy is middleware that proxies requests.
package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Proxy represents a middleware instance that can proxy requests.
type Proxy struct {
	Next  middleware.Handler
	Rules []Rule
}

// ServeHTTP satisfies the middleware.Handler interface.
func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	for _, rule := range p.Rules {
		if middleware.Path(r.URL.Path).Matches(rule.From) {
			var base string

			if strings.HasPrefix(rule.To, "http") { // includes https
				// destination includes a scheme! no need to guess
				base = rule.To
			} else {
				// no scheme specified; assume same as request
				var scheme string
				if r.TLS == nil {
					scheme = "http"
				} else {
					scheme = "https"
				}
				base = scheme + "://" + rule.To
			}

			baseUrl, err := url.Parse(base)
			if err != nil {
				return http.StatusInternalServerError, err
			}
			r.Host = baseUrl.Host

			// TODO: Construct this before; not during every request, if possible
			proxy := httputil.NewSingleHostReverseProxy(baseUrl)
			proxy.ServeHTTP(w, r)
			return 0, nil
		}
	}

	return p.Next.ServeHTTP(w, r)
}

// New creates a new instance of proxy middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return Proxy{Next: next, Rules: rules}
	}, nil
}

func parse(c middleware.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		var rule Rule
		if !c.Args(&rule.From, &rule.To) {
			return rules, c.ArgErr()
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

type Rule struct {
	From, To string
}
