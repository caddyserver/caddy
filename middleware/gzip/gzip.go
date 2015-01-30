// Package gzip provides a simple middleware layer that performs
// gzip compression on the response.
package gzip

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// New creates a new gzip middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {
	return func(next http.HandlerFunc) http.HandlerFunc {
		gz := Gzip{Next: next}
		return gz.ServeHTTP
	}, nil
}

// Gzip is a http.Handler middleware type which gzips HTTP responses.
type Gzip struct {
	Next http.HandlerFunc
	// TODO: Compression level, other settings
}

// ServeHTTP serves a gzipped response if the client supports it.
func (g Gzip) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		g.Next(w, r)
		return
	}
	w.Header().Set("Content-Encoding", "gzip")
	gzipWriter := gzip.NewWriter(w)
	defer gzipWriter.Close()
	gz := gzipResponseWriter{Writer: gzipWriter, ResponseWriter: w}
	g.Next(gz, r)
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
