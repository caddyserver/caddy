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

// Package internalsrv provides a simple middleware that (a) prevents access
// to internal locations and (b) allows to return files from internal location
// by setting a special header, e.g. in a proxy response.
//
// The package is named internalsrv so as not to conflict with Go tooling
// convention which treats folders called "internal" differently.
package internalsrv

import (
	"net/http"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

// Internal middleware protects internal locations from external requests -
// but allows access from the inside by using a special HTTP header.
type Internal struct {
	Next  httpserver.Handler
	Paths []string
}

const (
	redirectHeader        string = "X-Accel-Redirect"
	contentLengthHeader   string = "Content-Length"
	contentEncodingHeader string = "Content-Encoding"
	maxRedirectCount      int    = 10
)

func isInternalRedirect(w http.ResponseWriter) bool {
	return w.Header().Get(redirectHeader) != ""
}

// ServeHTTP implements the httpserver.Handler interface.
func (i Internal) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// Internal location requested? -> Not found.
	for _, prefix := range i.Paths {
		if httpserver.Path(r.URL.Path).Matches(prefix) {
			return http.StatusNotFound, nil
		}
	}

	// Use internal response writer to ignore responses that will be
	// redirected to internal locations
	iw := internalResponseWriter{ResponseWriterWrapper: &httpserver.ResponseWriterWrapper{ResponseWriter: w}}
	status, err := i.Next.ServeHTTP(iw, r)

	for c := 0; c < maxRedirectCount && isInternalRedirect(iw); c++ {
		// Redirect - adapt request URL path and send it again
		// "down the chain"
		r.URL.Path = iw.Header().Get(redirectHeader)
		iw.ClearHeader()
		status, err = i.Next.ServeHTTP(iw, r)
	}

	if isInternalRedirect(iw) {
		// Too many redirect cycles
		iw.ClearHeader()
		return http.StatusInternalServerError, nil
	}

	return status, err
}

// internalResponseWriter wraps the underlying http.ResponseWriter and ignores
// calls to Write and WriteHeader if the response should be redirected to an
// internal location.
type internalResponseWriter struct {
	*httpserver.ResponseWriterWrapper
}

// ClearHeader removes script headers that would interfere with follow up
// redirect requests.
func (w internalResponseWriter) ClearHeader() {
	w.Header().Del(redirectHeader)
	w.Header().Del(contentLengthHeader)
	w.Header().Del(contentEncodingHeader)
}

// WriteHeader ignores the call if the response should be redirected to an
// internal location.
func (w internalResponseWriter) WriteHeader(code int) {
	if !isInternalRedirect(w) {
		w.ResponseWriterWrapper.WriteHeader(code)
	}
}

// Write ignores the call if the response should be redirected to an internal
// location.
func (w internalResponseWriter) Write(b []byte) (int, error) {
	if isInternalRedirect(w) {
		return 0, nil
	}
	return w.ResponseWriterWrapper.Write(b)
}

// Interface guards
var _ httpserver.HTTPInterfaces = internalResponseWriter{}
