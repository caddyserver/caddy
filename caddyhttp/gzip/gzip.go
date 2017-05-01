// Package gzip provides a middleware layer that performs
// gzip compression on the response.
package gzip

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("gzip", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})

	initWriterPool()
}

// Gzip is a middleware type which gzips HTTP responses. It is
// imperative that any handler which writes to a gzipped response
// specifies the Content-Type, otherwise some clients will assume
// application/x-gzip and try to download a file.
type Gzip struct {
	Next    httpserver.Handler
	Configs []Config
}

// Config holds the configuration for Gzip middleware
type Config struct {
	RequestFilters  []RequestFilter
	ResponseFilters []ResponseFilter
	Level           int // Compression level
}

// ServeHTTP serves a gzipped response if the client supports it.
func (g Gzip) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return g.Next.ServeHTTP(w, r)
	}
outer:
	for _, c := range g.Configs {

		// Check request filters to determine if gzipping is permitted for this request
		for _, filter := range c.RequestFilters {
			if !filter.ShouldCompress(r) {
				continue outer
			}
		}

		// gzipWriter modifies underlying writer at init,
		// use a discard writer instead to leave ResponseWriter in
		// original form.
		gzipWriter := getWriter(c.Level)
		defer putWriter(c.Level, gzipWriter)
		gz := &gzipResponseWriter{Writer: gzipWriter, ResponseWriter: w}

		var rw http.ResponseWriter
		// if no response filter is used
		if len(c.ResponseFilters) == 0 {
			// replace discard writer with ResponseWriter
			gzipWriter.Reset(w)
			rw = gz
		} else {
			// wrap gzip writer with ResponseFilterWriter
			rw = NewResponseFilterWriter(c.ResponseFilters, gz)
		}

		// Any response in forward middleware will now be compressed
		status, err := g.Next.ServeHTTP(rw, r)

		// If there was an error that remained unhandled, we need
		// to send something back before gzipWriter gets closed at
		// the return of this method!
		if status >= 400 {
			httpserver.DefaultErrorFunc(w, r, status)
			return 0, err
		}
		return status, err
	}

	// no matching filter
	return g.Next.ServeHTTP(w, r)
}

// gzipResponeWriter wraps the underlying Write method
// with a gzip.Writer to compress the output.
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
	statusCodeWritten bool
}

// WriteHeader wraps the underlying WriteHeader method to prevent
// problems with conflicting headers from proxied backends. For
// example, a backend system that calculates Content-Length would
// be wrong because it doesn't know it's being gzipped.
func (w *gzipResponseWriter) WriteHeader(code int) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Add("Vary", "Accept-Encoding")
	w.ResponseWriter.WriteHeader(code)
	w.statusCodeWritten = true
}

// Write wraps the underlying Write method to do compression.
func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", http.DetectContentType(b))
	}
	if !w.statusCodeWritten {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.Writer.Write(b)
	return n, err
}

// Hijack implements http.Hijacker. It simply wraps the underlying
// ResponseWriter's Hijack method if there is one, or returns an error.
func (w *gzipResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, httpserver.NonHijackerError{Underlying: w.ResponseWriter}
}

// Flush implements http.Flusher. It simply wraps the underlying
// ResponseWriter's Flush method if there is one, or panics.
func (w *gzipResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	} else {
		panic(httpserver.NonFlusherError{Underlying: w.ResponseWriter}) // should be recovered at the beginning of middleware stack
	}
}

// CloseNotify implements http.CloseNotifier.
// It just inherits the underlying ResponseWriter's CloseNotify method.
func (w *gzipResponseWriter) CloseNotify() <-chan bool {
	if cn, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	panic(httpserver.NonCloseNotifierError{Underlying: w.ResponseWriter})
}

func (w *gzipResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, hasPusher := w.ResponseWriter.(http.Pusher); hasPusher {
		return pusher.Push(target, opts)
	}

	return httpserver.NonFlusherError{Underlying: w.ResponseWriter}
}

// Interface guards
var _ http.Pusher = (*gzipResponseWriter)(nil)
var _ http.Flusher = (*gzipResponseWriter)(nil)
var _ http.CloseNotifier = (*gzipResponseWriter)(nil)
var _ http.Hijacker = (*gzipResponseWriter)(nil)
