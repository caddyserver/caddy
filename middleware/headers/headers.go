package headers

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// Headers is middleware that adds headers to the responses
// for requests matching a certain path.
type Headers struct {
	next  http.HandlerFunc
	rules []headers
}

// ServeHTTP implements the http.Handler interface and serves the requests,
// adding headers to the response according to the configured rules.
func (h *Headers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, rule := range h.rules {
		if middleware.Path(r.URL.Path).Matches(rule.Url) {
			for _, header := range rule.Headers {
				w.Header().Set(header.Name, header.Value)
			}
		}
	}
	h.next(w, r)
}

type (
	// Headers groups a slice of HTTP headers by a URL pattern.
	// TODO: use http.Header type instead??
	headers struct {
		Url     string
		Headers []header
	}

	// Header represents a single HTTP header, simply a name and value.
	header struct {
		Name  string
		Value string
	}
)
