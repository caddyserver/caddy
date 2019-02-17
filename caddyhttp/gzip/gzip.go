// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gzip provides a middleware layer that performs
// gzip compression on the response.
package gzip

import (
	"compress/gzip"
	"io"
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

		// In order to avoid unused memory allocation, gzip.putWriter only be called when gzip compression happened.
		// see https://github.com/mholt/caddy/issues/2395
		gz := &gzipResponseWriter{
			ResponseWriterWrapper: &httpserver.ResponseWriterWrapper{ResponseWriter: w},
			newWriter: func() io.Writer {
				// gzipWriter modifies underlying writer at init,
				// use a discard writer instead to leave ResponseWriter in
				// original form.
				return getWriter(c.Level)
			},
		}

		defer func() {
			if gzWriter, ok := gz.internalWriter.(*gzip.Writer); ok {
				putWriter(c.Level, gzWriter)
			}
		}()

		var rw http.ResponseWriter
		// if no response filter is used
		if len(c.ResponseFilters) == 0 {
			// replace discard writer with ResponseWriter
			if gzWriter, ok := gz.Writer().(*gzip.Writer); ok {
				gzWriter.Reset(w)
			}
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

// gzipResponseWriter wraps the underlying Write method
// with a gzip.Writer to compress the output.
type gzipResponseWriter struct {
	internalWriter io.Writer
	*httpserver.ResponseWriterWrapper
	statusCodeWritten bool
	newWriter         func() io.Writer
}

// WriteHeader wraps the underlying WriteHeader method to prevent
// problems with conflicting headers from proxied backends. For
// example, a backend system that calculates Content-Length would
// be wrong because it doesn't know it's being gzipped.
func (w *gzipResponseWriter) WriteHeader(code int) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Add("Vary", "Accept-Encoding")
	originalEtag := w.Header().Get("ETag")
	if originalEtag != "" && !strings.HasPrefix(originalEtag, "W/") {
		w.Header().Set("ETag", "W/"+originalEtag)
	}
	w.ResponseWriterWrapper.WriteHeader(code)
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
	n, err := w.Writer().Write(b)
	return n, err
}

//Writer use a lazy way to initialize Writer
func (w *gzipResponseWriter) Writer() io.Writer {
	if w.internalWriter == nil {
		w.internalWriter = w.newWriter()
	}
	return w.internalWriter
}

// Interface guards
var _ httpserver.HTTPInterfaces = (*gzipResponseWriter)(nil)
