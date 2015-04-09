// Package gzip provides a simple middleware layer that performs
// gzip compression on the response.
package gzip

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Gzip is a middleware type which gzips HTTP responses. It is
// imperative that any handler which writes to a gzipped response
// specifies the Content-Type, otherwise some clients will assume
// application/x-gzip and try to download a file.
type Gzip struct {
	Next middleware.Handler
}

// New creates a new gzip middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {
	return func(next middleware.Handler) middleware.Handler {
		return Gzip{Next: next}
	}, nil
}

// ServeHTTP serves a gzipped response if the client supports it.
func (g Gzip) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return g.Next.ServeHTTP(w, r)
	}

	w.Header().Set("Content-Encoding", "gzip")
	gzipWriter := gzip.NewWriter(w)
	defer gzipWriter.Close()
	gz := gzipResponseWriter{Writer: gzipWriter, ResponseWriter: w}

	// Any response in forward middleware will now be compressed
	status, err := g.Next.ServeHTTP(gz, r)

	// If there was an error that remained unhandled, we need
	// to send something back before gzipWriter gets closed at
	// the return of this method!
	if status >= 400 {
		gz.Header().Set("Content-Type", "text/plain") // very necessary
		gz.WriteHeader(status)
		fmt.Fprintf(gz, "%d %s", status, http.StatusText(status))
		return 0, err
	} else {
		return status, err
	}
}

// gzipResponeWriter wraps the underlying Write method
// with a gzip.Writer to compress the output.
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

// Write wraps the underlying Write method to do compression.
func (w gzipResponseWriter) Write(b []byte) (int, error) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", http.DetectContentType(b))
	}
	n, err := w.Writer.Write(b)
	return n, err
}
