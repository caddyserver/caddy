// Package header provides middleware that appends headers to
// requests based on a set of configuration rules that define
// which routes receive which headers.
package header

import (
	"bufio"
	"net"
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
	rww := &responseWriterWrapper{w: w}
	for _, rule := range h.Rules {
		if httpserver.Path(r.URL.Path).Matches(rule.Path) {
			for _, header := range rule.Headers {
				// One can either delete a header, add multiple values to a header, or simply
				// set a header.
				if strings.HasPrefix(header.Name, "-") {
					rww.delHeader(strings.TrimLeft(header.Name, "-"))
				} else if strings.HasPrefix(header.Name, "+") {
					rww.Header().Add(strings.TrimLeft(header.Name, "+"), replacer.Replace(header.Value))
				} else {
					rww.Header().Set(header.Name, replacer.Replace(header.Value))
				}
			}
		}
	}
	return h.Next.ServeHTTP(rww, r)
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

// headerOperation represents an operation on the header
type headerOperation func(http.Header)

// responseWriterWrapper wraps the real ResponseWriter.
// It defers header operations until writeHeader
type responseWriterWrapper struct {
	w           http.ResponseWriter
	ops         []headerOperation
	wroteHeader bool
}

func (rww *responseWriterWrapper) Header() http.Header {
	return rww.w.Header()
}

func (rww *responseWriterWrapper) Write(d []byte) (int, error) {
	if !rww.wroteHeader {
		rww.WriteHeader(http.StatusOK)
	}
	return rww.w.Write(d)
}

func (rww *responseWriterWrapper) WriteHeader(status int) {
	if rww.wroteHeader {
		return
	}
	rww.wroteHeader = true
	// capture the original headers
	h := rww.Header()

	// perform our revisions
	for _, op := range rww.ops {
		op(h)
	}

	rww.w.WriteHeader(status)
}

// delHeader deletes the existing header according to the key
// Also it will delete that header added later.
func (rww *responseWriterWrapper) delHeader(key string) {
	// remove the existing one if any
	rww.Header().Del(key)

	// register a future deletion
	rww.ops = append(rww.ops, func(h http.Header) {
		h.Del(key)
	})
}

// Hijack implements http.Hijacker. It simply wraps the underlying
// ResponseWriter's Hijack method if there is one, or returns an error.
func (rww *responseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rww.w.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, httpserver.NonHijackerError{Underlying: rww.w}
}
