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

package push

import (
	"net/http"
	"strings"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func (h Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	pusher, hasPusher := w.(http.Pusher)

	// no push possible, carry on
	if !hasPusher {
		return h.Next.ServeHTTP(w, r)
	}

	// check if this is a request for the pushed resource (avoid recursion)
	if _, exists := r.Header[pushHeader]; exists {
		return h.Next.ServeHTTP(w, r)
	}

	headers := h.filterProxiedHeaders(r.Header)

	// push first
outer:
	for _, rule := range h.Rules {
		urlPath := r.URL.Path
		matches := httpserver.Path(urlPath).Matches(rule.Path)
		// Also check IndexPages when requesting a directory
		if !matches {
			indexFile, isIndexFile := httpserver.IndexFile(h.Root, urlPath, h.indexPages)
			if isIndexFile {
				matches = httpserver.Path(indexFile).Matches(rule.Path)
			}
		}
		if matches {
			for _, resource := range rule.Resources {
				pushErr := pusher.Push(resource.Path, &http.PushOptions{
					Method: resource.Method,
					Header: h.mergeHeaders(headers, resource.Header),
				})
				if pushErr != nil {
					// if we cannot push (either not supported or concurrent streams are full - break)
					break outer
				}
			}
		}
	}

	// serve later
	code, err := h.Next.ServeHTTP(w, r)

	// push resources returned in Link headers from upstream middlewares or proxied apps
	if links, exists := w.Header()["Link"]; exists {
		h.servePreloadLinks(pusher, headers, links)
	}

	return code, err
}

// servePreloadLinks parses Link headers from backend and pushes resources found in them.
// For accepted header formats check parseLinkHeader function.
//
// If resource has 'nopush' attribute then it will be omitted.
func (h Middleware) servePreloadLinks(pusher http.Pusher, headers http.Header, resources []string) {
outer:
	for _, resource := range resources {
		for _, resource := range parseLinkHeader(resource) {
			if _, exists := resource.params["nopush"]; exists {
				continue
			}

			if h.isRemoteResource(resource.uri) {
				continue
			}

			err := pusher.Push(resource.uri, &http.PushOptions{
				Method: http.MethodGet,
				Header: headers,
			})

			if err != nil {
				break outer
			}
		}
	}
}

func (h Middleware) isRemoteResource(resource string) bool {
	return strings.HasPrefix(resource, "//") ||
		strings.HasPrefix(resource, "http://") ||
		strings.HasPrefix(resource, "https://")
}

func (h Middleware) mergeHeaders(l, r http.Header) http.Header {
	out := http.Header{}

	for k, v := range l {
		out[k] = v
	}

	for k, vv := range r {
		for _, v := range vv {
			out.Add(k, v)
		}
	}

	return out
}

func (h Middleware) filterProxiedHeaders(headers http.Header) http.Header {
	filter := http.Header{}

	for _, header := range proxiedHeaders {
		if val, ok := headers[header]; ok {
			filter[header] = val
		}
	}

	return filter
}

var proxiedHeaders = []string{
	"Accept-Encoding",
	"Accept-Language",
	"Cache-Control",
	"Host",
	"User-Agent",
}
