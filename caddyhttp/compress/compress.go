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

// Package compress provides a middleware layer that performs
// compression on the response.
package compress

import (
	"io"
	"net/http"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("compress", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
	initGzipWriterPool()
	initZstdWriterPool()

}

// Compress is a middleware type which compresses HTTP responses. It is
// imperative that any handler which writes to a compressed response
// specifies the Content-Type, otherwise some clients will assume
// application/* and try to download a file.
type Compress struct {
	Next    httpserver.Handler
	Configs []Config
}

// Config holds the configuration for Compress middleware
type Config struct {
	RequestFilters  []RequestFilter
	ResponseFilters []ResponseFilter
	Level           int // Compression level
	Scheme string // the compression scheme used
}

// ServeHTTP serves a compressed response if the client supports it.
func (g Compress) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	// TODO_DARSHANIME
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return g.Next.ServeHTTP(w, r)
	}

outer:
	for _, c := range g.Configs {
		// Check request filters to determine if compressing is permitted for this request
		for _, filter := range c.RequestFilters {
			if !filter.ShouldCompress(r) {
				continue outer
			}
		}

		// compressWriter modifies underlying writer at init,
		// use a discard writer instead to leave ResponseWriter in
		// original form.
		compressWriter, err := getWriter(c)
		if err != nil {
			return 0, err
		}
		defer putWriter(c, compressWriter)
		cz := &compressResponseWriter{
			Writer:                compressWriter,
			ResponseWriterWrapper: &httpserver.ResponseWriterWrapper{ResponseWriter: w},
			Scheme: c.Scheme,
		}

		// if no filters are used, (the first branch of if), use vanilla compressResponewriter
		// if filters are used, use ResponseFilterWriter which has compressResponseWriter and some more fields to
		// keep track of ignored responses etc
		var rw http.ResponseWriter
		// if no response filter is used
		if len(c.ResponseFilters) == 0 {
			// replace discard writer with ResponseWriter
			compressWriter.Reset(w)
			rw = cz
		} else {
			// wrap compress writer with ResponseFilterWriter
			rw = NewResponseFilterWriter(c.ResponseFilters, cz)
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

// compressResponeWriter wraps the underlying Write method
// with a io.Writer to compress the output.
type compressResponseWriter struct {
	io.Writer
	*httpserver.ResponseWriterWrapper
	statusCodeWritten bool
	Scheme string
}

type compressWriter interface {
	io.Writer
	io.Closer
	Reset (io.Writer)
}

// These 2 methods are called by Caddy for all the plugins - much like ServeHTTP

// WriteHeader wraps the underlying WriteHeader method to prevent
// problems with conflicting headers from proxied backends. For
// example, a backend system that calculates Content-Length would
// be wrong because it doesn't know it's being gzipped.
func (w *compressResponseWriter) WriteHeader(code int) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", w.Scheme)
	w.Header().Add("Vary", "Accept-Encoding")
	originalEtag := w.Header().Get("ETag")
	if originalEtag != "" && !strings.HasPrefix(originalEtag, "W/") {
		w.Header().Set("ETag", "W/"+originalEtag)
	}
	w.ResponseWriterWrapper.WriteHeader(code)
	w.statusCodeWritten = true
}

// Write wraps the underlying Write method to do compression.
func (w *compressResponseWriter) Write(b []byte) (int, error) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", http.DetectContentType(b))
	}
	if !w.statusCodeWritten {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.Writer.Write(b)
	return n, err
}

// Interface guards
var _ httpserver.HTTPInterfaces = (*compressResponseWriter)(nil)
