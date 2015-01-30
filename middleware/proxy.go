package middleware

import (
	"log"
	"net/http"
	"strings"
)

// Proxy is middleware that proxies requests.
func Proxy(p parser) Middleware {
	var rules []proxyRule

	for p.Next() {
		rule := proxyRule{}

		if !p.Args(&rule.from, &rule.to) {
			return p.ArgErr()
		}

		rules = append(rules, rule)
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			for _, rule := range rules {
				if Path(r.URL.Path).Matches(rule.from) {
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
	}
}

type proxyRule struct {
	from string
	to   string
}
