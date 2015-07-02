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
	Next    middleware.Handler
	Configs []Config
}

// Config holds the configuration for Gzip middleware
type Config struct {
	Filters []Filter // Filters to use
	Level   int      // Compression level
}

// ServeHTTP serves a gzipped response if the client supports it.
func (g Gzip) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return g.Next.ServeHTTP(w, r)
	}

outer:
	for _, c := range g.Configs {

		// Check filters to determine if gzipping is permitted for this request
		for _, filter := range c.Filters {
			if !filter.ShouldCompress(r) {
				continue outer
			}
		}

		// Delete this header so gzipping is not repeated later in the chain
		r.Header.Del("Accept-Encoding")

		w.Header().Set("Content-Encoding", "gzip")
		gzipWriter, err := newWriter(c, w)
		if err != nil {
			// should not happen
			return http.StatusInternalServerError, err
		}
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
		}
		return status, err
	}

	// no matching filter
	return g.Next.ServeHTTP(w, r)
}

// newWriter create a new Gzip Writer based on the compression level.
// If the level is valid (i.e. between 1 and 9), it uses the level.
// Otherwise, it uses default compression level.
func newWriter(c Config, w http.ResponseWriter) (*gzip.Writer, error) {
	if c.Level >= gzip.BestSpeed && c.Level <= gzip.BestCompression {
		return gzip.NewWriterLevel(w, c.Level)
	}
	return gzip.NewWriter(w), nil
}

// gzipResponeWriter wraps the underlying Write method
// with a gzip.Writer to compress the output.
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

// WriteHeader wraps the underlying WriteHeader method to prevent
// problems with conflicting headers from proxied backends. For
// example, a backend system that calculates Content-Length would
// be wrong because it doesn't know it's being gzipped.
func (w gzipResponseWriter) WriteHeader(code int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(code)
}

// Write wraps the underlying Write method to do compression.
func (w gzipResponseWriter) Write(b []byte) (int, error) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", http.DetectContentType(b))
	}
	n, err := w.Writer.Write(b)
	return n, err
}
