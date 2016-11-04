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
			for name := range rule.Headers {

				// One can either delete a header, add multiple values to a header, or simply
				// set a header.

				if strings.HasPrefix(name, "-") {
					rww.delHeader(strings.TrimLeft(name, "-"))
				} else if strings.HasPrefix(name, "+") {
					for _, value := range rule.Headers[name] {
						rww.Header().Add(strings.TrimLeft(name, "+"), replacer.Replace(value))
					}
				} else {
					for _, value := range rule.Headers[name] {
						rww.Header().Set(name, replacer.Replace(value))
					}
				}
			}
		}
	}
	return h.Next.ServeHTTP(rww, r)
}

type (
	// Rule groups a slice of HTTP headers by a URL pattern.
	Rule struct {
		Path    string
		Headers http.Header
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

// Flush implements http.Flusher. It simply wraps the underlying
// ResponseWriter's Flush method if there is one, or panics.
func (rww *responseWriterWrapper) Flush() {
	if f, ok := rww.w.(http.Flusher); ok {
		f.Flush()
	} else {
		panic(httpserver.NonFlusherError{Underlying: rww.w}) // should be recovered at the beginning of middleware stack
	}
}

// CloseNotify implements http.CloseNotifier.
// It just inherits the underlying ResponseWriter's CloseNotify method.
// It panics if the underlying ResponseWriter is not a CloseNotifier.
func (rww *responseWriterWrapper) CloseNotify() <-chan bool {
	if cn, ok := rww.w.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	panic(httpserver.NonCloseNotifierError{Underlying: rww.w})
}
