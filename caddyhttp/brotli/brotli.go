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

// Package brotli provides a middleware layer that performs
// brotli compression on the response.
package brotli

import (
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("brotli", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})

	initWriterPool()
}

// Brotli is a middleware type which compresses HTTP responses. It is
// imperative that any handler which writes to a compressed response
// specifies the Content-Type, otherwise some clients will assume
// application/x-brotli and try to download a file.
type Brotli struct {
	Next    httpserver.Handler
	Configs []Config
}

// Config holds the configuration for Brotli middleware
type Config struct {
	RequestFilters  []RequestFilter
	ResponseFilters []ResponseFilter
	Level           int // Compression level
}

// ServeHTTP serves a compressed response if the client supports it.
func (g Brotli) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "br") {
		return g.Next.ServeHTTP(w, r)
	}
outer:
	for _, c := range g.Configs {

		// Check request filters to determine if compression is permitted for this request
		for _, filter := range c.RequestFilters {
			if !filter.ShouldCompress(r) {
				continue outer
			}
		}

		// In order to avoid unused memory allocation, brotli.putWriter only be called when brotli compression happened.
		// see https://github.com/mholt/caddy/issues/2395
		br := &brotliResponseWriter{
			ResponseWriterWrapper: &httpserver.ResponseWriterWrapper{ResponseWriter: w},
			newWriter: func() io.Writer {
				// brotliWriter modifies underlying writer at init,
				// use a discard writer instead to leave ResponseWriter in
				// original form.
				return getWriter(c.Level)
			},
		}

		defer func() {
			if brWriter, ok := br.internalWriter.(*brotli.Writer); ok {
				putWriter(c.Level, brWriter)
			}
		}()

		var rw http.ResponseWriter
		// if no response filter is used
		if len(c.ResponseFilters) == 0 {
			// replace discard writer with ResponseWriter
			if brWriter, ok := br.Writer().(*brotli.Writer); ok {
				brWriter.Reset(w)
			}
			rw = br
		} else {
			// wrap brotli writer with ResponseFilterWriter
			rw = NewResponseFilterWriter(c.ResponseFilters, br)
		}

		// Any response in forward middleware will now be compressed
		status, err := g.Next.ServeHTTP(rw, r)

		// If there was an error that remained unhandled, we need
		// to send something back before brotliWriter gets closed at
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

// brotliResponseWriter wraps the underlying Write method
// with a brotli.Writer to compress the output.
type brotliResponseWriter struct {
	internalWriter io.Writer
	*httpserver.ResponseWriterWrapper
	statusCodeWritten bool
	newWriter         func() io.Writer
}

// WriteHeader wraps the underlying WriteHeader method to prevent
// problems with conflicting headers from proxied backends. For
// example, a backend system that calculates Content-Length would
// be wrong because it doesn't know it's being compressed.
func (w *brotliResponseWriter) WriteHeader(code int) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", "br")
	w.Header().Add("Vary", "Accept-Encoding")
	originalEtag := w.Header().Get("ETag")
	if originalEtag != "" && !strings.HasPrefix(originalEtag, "W/") {
		w.Header().Set("ETag", "W/"+originalEtag)
	}
	w.ResponseWriterWrapper.WriteHeader(code)
	w.statusCodeWritten = true
}

// Write wraps the underlying Write method to do compression.
func (w *brotliResponseWriter) Write(b []byte) (int, error) {
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
func (w *brotliResponseWriter) Writer() io.Writer {
	if w.internalWriter == nil {
		w.internalWriter = w.newWriter()
	}
	return w.internalWriter
}

// Interface guards
var _ httpserver.HTTPInterfaces = (*brotliResponseWriter)(nil)
