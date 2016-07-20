// Package header provides middleware that appends headers to
// requests based on a set of configuration rules that define
// which routes receive which headers.
package header

import (
	"net/http"
	"strings"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Headers is middleware that adds headers to the responses
// for requests matching a certain path.
type Headers struct {
	Next  httpserver.Handler
	Rules []Rule
}

// ServeHTTP implements the httpserver.Handler interface and serves requests,
// setting headers on the response according to the configured rules.
func (h Headers) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	replacer := httpserver.NewReplacer(r, nil, "")
	for _, rule := range h.Rules {
		if httpserver.Path(r.URL.Path).Matches(rule.Path) {
			for _, header := range rule.Headers {
				// One can either delete a header, add multiple values to a header, or simply
				// set a header.
				if strings.HasPrefix(header.Name, "-") {
					w.Header().Del(strings.TrimLeft(header.Name, "-"))
				} else if strings.HasPrefix(header.Name, "+") {
					w.Header().Add(strings.TrimLeft(header.Name, "+"), replacer.Replace(header.Value))
				} else {
					w.Header().Set(header.Name, replacer.Replace(header.Value))
				}
			}
		}
	}
	return h.Next.ServeHTTP(w, r)
}

type (
	// Rule groups a slice of HTTP headers by a URL pattern.
	// TODO: use http.Header type instead?
	Rule struct {
		Path    string
		Headers []Header
	}

	// Header represents a single HTTP header, simply a name and value.
	Header struct {
		Name  string
		Value string
	}
)
