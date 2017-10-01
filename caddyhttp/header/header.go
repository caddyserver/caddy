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

// Package header provides middleware that appends headers to
// requests based on a set of configuration rules that define
// which routes receive which headers.
package header

import (
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
	rww := &responseWriterWrapper{
		ResponseWriterWrapper: &httpserver.ResponseWriterWrapper{ResponseWriter: w},
	}
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
	*httpserver.ResponseWriterWrapper
	ops         []headerOperation
	wroteHeader bool
}

func (rww *responseWriterWrapper) Header() http.Header {
	return rww.ResponseWriterWrapper.Header()
}

func (rww *responseWriterWrapper) Write(d []byte) (int, error) {
	if !rww.wroteHeader {
		rww.WriteHeader(http.StatusOK)
	}
	return rww.ResponseWriterWrapper.Write(d)
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

	rww.ResponseWriterWrapper.WriteHeader(status)
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

// Interface guards
var _ httpserver.HTTPInterfaces = (*responseWriterWrapper)(nil)
