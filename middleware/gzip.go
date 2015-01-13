package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

// Adapted from https://gist.github.com/the42/1956518

// Gzip is middleware that gzip-compresses the response.
func Gzip(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gzipWriter := gzip.NewWriter(w)
		defer gzipWriter.Close()
		gz := gzipResponseWriter{Writer: gzipWriter, ResponseWriter: w}
		next(gz, r)
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
	return w.Writer.Write(b)
}
