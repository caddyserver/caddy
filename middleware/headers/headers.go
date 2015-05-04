// Package headers provides middleware that appends headers to
// requests based on a set of configuration rules that define
// which routes receive which headers.
package headers

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// Headers is middleware that adds headers to the responses
// for requests matching a certain path.
type Headers struct {
	Next  middleware.Handler
	Rules []Rule
}

// ServeHTTP implements the middleware.Handler interface and serves requests,
// adding headers to the response according to the configured rules.
func (h Headers) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range h.Rules {
		if middleware.Path(r.URL.Path).Matches(rule.Url) {
			for _, header := range rule.Headers {
				w.Header().Set(header.Name, header.Value)
			}
		}
	}
	return h.Next.ServeHTTP(w, r)
}

type (
	// Rule groups a slice of HTTP headers by a URL pattern.
	// TODO: use http.Header type instead?
	Rule struct {
		Url     string
		Headers []Header
	}

	// Header represents a single HTTP header, simply a name and value.
	Header struct {
		Name  string
		Value string
	}
)
