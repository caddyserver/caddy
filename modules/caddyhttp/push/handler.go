// Copyright 2015 Matthew Holt and The Caddy Authors
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
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a middleware for HTTP/2 server push. Note that
// HTTP/2 server push has been deprecated by some clients and
// its use is discouraged unless you can accurately predict
// which resources actually need to be pushed to the client;
// it can be difficult to know what the client already has
// cached. Pushing unnecessary resources results in worse
// performance. Consider using HTTP 103 Early Hints instead.
//
// This handler supports pushing from Link headers; in other
// words, if the eventual response has Link headers, this
// handler will push the resources indicated by those headers,
// even without specifying any resources in its config.
type Handler struct {
	// The resources to push.
	Resources []Resource `json:"resources,omitempty"`

	// Headers to modify for the push requests.
	Headers *HeaderConfig `json:"headers,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.push",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up h.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.Headers != nil {
		err := h.Headers.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning header operations: %v", err)
		}
	}
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	pusher, ok := w.(http.Pusher)
	if !ok {
		return next.ServeHTTP(w, r)
	}

	// short-circuit recursive pushes
	if _, ok := r.Header[pushHeader]; ok {
		return next.ServeHTTP(w, r)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	server := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	shouldLogCredentials := server.Logs != nil && server.Logs.ShouldLogCredentials

	// create header for push requests
	hdr := h.initializePushHeaders(r, repl)

	// push first!
	for _, resource := range h.Resources {
		if c := h.logger.Check(zapcore.DebugLevel, "pushing resource"); c != nil {
			c.Write(
				zap.String("uri", r.RequestURI),
				zap.String("push_method", resource.Method),
				zap.String("push_target", resource.Target),
				zap.Object("push_headers", caddyhttp.LoggableHTTPHeader{
					Header:               hdr,
					ShouldLogCredentials: shouldLogCredentials,
				}),
			)
		}
		err := pusher.Push(repl.ReplaceAll(resource.Target, "."), &http.PushOptions{
			Method: resource.Method,
			Header: hdr,
		})
		if err != nil {
			// usually this means either that push is not
			// supported or concurrent streams are full
			break
		}
	}

	// wrap the response writer so that we can initiate push of any resources
	// described in Link header fields before the response is written
	lp := linkPusher{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		handler:               h,
		pusher:                pusher,
		header:                hdr,
		request:               r,
	}

	// serve only after pushing!
	if err := next.ServeHTTP(lp, r); err != nil {
		return err
	}

	return nil
}

func (h Handler) initializePushHeaders(r *http.Request, repl *caddy.Replacer) http.Header {
	hdr := make(http.Header)

	// prevent recursive pushes
	hdr.Set(pushHeader, "1")

	// set initial header fields; since exactly how headers should
	// be implemented for server push is not well-understood, we
	// are being conservative for now like httpd is:
	// https://httpd.apache.org/docs/2.4/en/howto/http2.html#push
	// we only copy some well-known, safe headers that are likely
	// crucial when requesting certain kinds of content
	for _, fieldName := range safeHeaders {
		if vals, ok := r.Header[fieldName]; ok {
			hdr[fieldName] = vals
		}
	}

	// user can customize the push request headers
	if h.Headers != nil {
		h.Headers.ApplyTo(hdr, repl)
	}

	return hdr
}

// servePreloadLinks parses Link headers from upstream and pushes
// resources described by them. If a resource has the "nopush"
// attribute or describes an external entity (meaning, the resource
// URI includes a scheme), it will not be pushed.
func (h Handler) servePreloadLinks(pusher http.Pusher, hdr http.Header, resources []string) {
	for _, resource := range resources {
		for _, resource := range parseLinkHeader(resource) {
			if _, ok := resource.params["nopush"]; ok {
				continue
			}
			if isRemoteResource(resource.uri) {
				continue
			}
			err := pusher.Push(resource.uri, &http.PushOptions{
				Header: hdr,
			})
			if err != nil {
				return
			}
		}
	}
}

// Resource represents a request for a resource to push.
type Resource struct {
	// Method is the request method, which must be GET or HEAD.
	// Default is GET.
	Method string `json:"method,omitempty"`

	// Target is the path to the resource being pushed.
	Target string `json:"target,omitempty"`
}

// HeaderConfig configures headers for synthetic push requests.
type HeaderConfig struct {
	headers.HeaderOps
}

// linkPusher is a http.ResponseWriter that intercepts
// the WriteHeader() call to ensure that any resources
// described by Link response headers get pushed before
// the response is allowed to be written.
type linkPusher struct {
	*caddyhttp.ResponseWriterWrapper
	handler Handler
	pusher  http.Pusher
	header  http.Header
	request *http.Request
}

func (lp linkPusher) WriteHeader(statusCode int) {
	if links, ok := lp.ResponseWriter.Header()["Link"]; ok {
		// only initiate these pushes if it hasn't been done yet
		if val := caddyhttp.GetVar(lp.request.Context(), pushedLink); val == nil {
			if c := lp.handler.logger.Check(zapcore.DebugLevel, "pushing Link resources"); c != nil {
				c.Write(zap.Strings("linked", links))
			}
			caddyhttp.SetVar(lp.request.Context(), pushedLink, true)
			lp.handler.servePreloadLinks(lp.pusher, lp.header, links)
		}
	}
	lp.ResponseWriter.WriteHeader(statusCode)
}

// isRemoteResource returns true if resource starts with
// a scheme or is a protocol-relative URI.
func isRemoteResource(resource string) bool {
	return strings.HasPrefix(resource, "//") ||
		strings.HasPrefix(resource, "http://") ||
		strings.HasPrefix(resource, "https://")
}

// safeHeaders is a list of header fields that are
// safe to copy to push requests implicitly. It is
// assumed that requests for certain kinds of content
// would fail without these fields present.
var safeHeaders = []string{
	"Accept-Encoding",
	"Accept-Language",
	"Accept",
	"Cache-Control",
	"User-Agent",
}

// pushHeader is a header field that gets added to push requests
// in order to avoid recursive/infinite pushes.
const pushHeader = "Caddy-Push"

// pushedLink is the key for the variable on the request
// context that we use to remember whether we have already
// pushed resources from Link headers yet; otherwise, if
// multiple push handlers are invoked, it would repeat the
// pushing of Link headers.
const pushedLink = "http.handlers.push.pushed_link"

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ http.ResponseWriter         = (*linkPusher)(nil)
	_ http.Pusher                 = (*linkPusher)(nil)
)
