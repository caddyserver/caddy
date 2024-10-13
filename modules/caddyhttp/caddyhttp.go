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

package caddyhttp

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(tlsPlaceholderWrapper{})
}

// RequestMatcher is a type that can match to a request.
// A route matcher MUST NOT modify the request, with the
// only exception being its context.
//
// Deprecated: Matchers should now implement RequestMatcherWithError.
// You may remove any interface guards for RequestMatcher
// but keep your Match() methods for backwards compatibility.
type RequestMatcher interface {
	Match(*http.Request) bool
}

// RequestMatcherWithError is like RequestMatcher but can return an error.
// An error during matching will abort the request middleware chain and
// invoke the error middleware chain.
//
// This will eventually replace RequestMatcher. Matcher modules
// should implement both interfaces, and once all modules have
// been updated to use RequestMatcherWithError, the RequestMatcher
// interface may eventually be dropped.
type RequestMatcherWithError interface {
	MatchWithError(*http.Request) (bool, error)
}

// Handler is like http.Handler except ServeHTTP may return an error.
//
// If any handler encounters an error, it should be returned for proper
// handling. Return values should be propagated down the middleware chain
// by returning it unchanged. Returned errors should not be re-wrapped
// if they are already HandlerError values.
type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
}

// HandlerFunc is a convenience type like http.HandlerFunc.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP implements the Handler interface.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// Middleware chains one Handler to the next by being passed
// the next Handler in the chain.
type Middleware func(Handler) Handler

// MiddlewareHandler is like Handler except it takes as a third
// argument the next handler in the chain. The next handler will
// never be nil, but may be a no-op handler if this is the last
// handler in the chain. Handlers which act as middleware should
// call the next handler's ServeHTTP method so as to propagate
// the request down the chain properly. Handlers which act as
// responders (content origins) need not invoke the next handler,
// since the last handler in the chain should be the first to
// write the response.
type MiddlewareHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request, Handler) error
}

// emptyHandler is used as a no-op handler.
var emptyHandler Handler = HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
	SetVar(req.Context(), "unhandled", true)
	return nil
})

// An implicit suffix middleware that, if reached, sets the StatusCode to the
// error stored in the ErrorCtxKey. This is to prevent situations where the
// Error chain does not actually handle the error (for instance, it matches only
// on some errors). See #3053
var errorEmptyHandler Handler = HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	httpError := r.Context().Value(ErrorCtxKey)
	if handlerError, ok := httpError.(HandlerError); ok {
		w.WriteHeader(handlerError.StatusCode)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	return nil
})

// ResponseHandler pairs a response matcher with custom handling
// logic. Either the status code can be changed to something else
// while using the original response body, or, if a status code
// is not set, it can execute a custom route list; this is useful
// for executing handler routes based on the properties of an HTTP
// response that has not been written out to the client yet.
//
// To use this type, provision it at module load time, then when
// ready to use, match the response against its matcher; if it
// matches (or doesn't have a matcher), change the status code on
// the response if configured; otherwise invoke the routes by
// calling `rh.Routes.Compile(next).ServeHTTP(rw, req)` (or similar).
type ResponseHandler struct {
	// The response matcher for this handler. If empty/nil,
	// it always matches.
	Match *ResponseMatcher `json:"match,omitempty"`

	// To write the original response body but with a different
	// status code, set this field to the desired status code.
	// If set, this takes priority over routes.
	StatusCode WeakString `json:"status_code,omitempty"`

	// The list of HTTP routes to execute if no status code is
	// specified. If evaluated, the original response body
	// will not be written.
	Routes RouteList `json:"routes,omitempty"`
}

// Provision sets up the routes in rh.
func (rh *ResponseHandler) Provision(ctx caddy.Context) error {
	if rh.Routes != nil {
		err := rh.Routes.Provision(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// WeakString is a type that unmarshals any JSON value
// as a string literal, with the following exceptions:
//
// 1. actual string values are decoded as strings; and
// 2. null is decoded as empty string;
//
// and provides methods for getting the value as various
// primitive types. However, using this type removes any
// type safety as far as deserializing JSON is concerned.
type WeakString string

// UnmarshalJSON satisfies json.Unmarshaler according to
// this type's documentation.
func (ws *WeakString) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return io.EOF
	}
	if b[0] == byte('"') && b[len(b)-1] == byte('"') {
		var s string
		err := json.Unmarshal(b, &s)
		if err != nil {
			return err
		}
		*ws = WeakString(s)
		return nil
	}
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	*ws = WeakString(b)
	return nil
}

// MarshalJSON marshals was a boolean if true or false,
// a number if an integer, or a string otherwise.
func (ws WeakString) MarshalJSON() ([]byte, error) {
	if ws == "true" {
		return []byte("true"), nil
	}
	if ws == "false" {
		return []byte("false"), nil
	}
	if num, err := strconv.Atoi(string(ws)); err == nil {
		return json.Marshal(num)
	}
	return json.Marshal(string(ws))
}

// Int returns ws as an integer. If ws is not an
// integer, 0 is returned.
func (ws WeakString) Int() int {
	num, _ := strconv.Atoi(string(ws))
	return num
}

// Float64 returns ws as a float64. If ws is not a
// float value, the zero value is returned.
func (ws WeakString) Float64() float64 {
	num, _ := strconv.ParseFloat(string(ws), 64)
	return num
}

// Bool returns ws as a boolean. If ws is not a
// boolean, false is returned.
func (ws WeakString) Bool() bool {
	return string(ws) == "true"
}

// String returns ws as a string.
func (ws WeakString) String() string {
	return string(ws)
}

// StatusCodeMatches returns true if a real HTTP status code matches
// the configured status code, which may be either a real HTTP status
// code or an integer representing a class of codes (e.g. 4 for all
// 4xx statuses).
func StatusCodeMatches(actual, configured int) bool {
	if actual == configured {
		return true
	}
	if configured < 100 &&
		actual >= configured*100 &&
		actual < (configured+1)*100 {
		return true
	}
	return false
}

// SanitizedPathJoin performs filepath.Join(root, reqPath) that
// is safe against directory traversal attacks. It uses logic
// similar to that in the Go standard library, specifically
// in the implementation of http.Dir. The root is assumed to
// be a trusted path, but reqPath is not; and the output will
// never be outside of root. The resulting path can be used
// with the local file system. If root is empty, the current
// directory is assumed. If the cleaned request path is deemed
// not local according to lexical processing (i.e. ignoring links),
// it will be rejected as unsafe and only the root will be returned.
func SanitizedPathJoin(root, reqPath string) string {
	if root == "" {
		root = "."
	}

	relPath := path.Clean("/" + reqPath)[1:] // clean path and trim the leading /
	if relPath != "" && !filepath.IsLocal(relPath) {
		// path is unsafe (see https://github.com/golang/go/issues/56336#issuecomment-1416214885)
		return root
	}

	path := filepath.Join(root, filepath.FromSlash(relPath))

	// filepath.Join also cleans the path, and cleaning strips
	// the trailing slash, so we need to re-add it afterwards.
	// if the length is 1, then it's a path to the root,
	// and that should return ".", so we don't append the separator.
	if strings.HasSuffix(reqPath, "/") && len(reqPath) > 1 {
		path += separator
	}

	return path
}

// CleanPath cleans path p according to path.Clean(), but only
// merges repeated slashes if collapseSlashes is true, and always
// preserves trailing slashes.
func CleanPath(p string, collapseSlashes bool) string {
	if collapseSlashes {
		return cleanPath(p)
	}

	// insert an invalid/impossible URI character into each two consecutive
	// slashes to expand empty path segments; then clean the path as usual,
	// and then remove the remaining temporary characters.
	const tmpCh = 0xff
	var sb strings.Builder
	for i, ch := range p {
		if ch == '/' && i > 0 && p[i-1] == '/' {
			sb.WriteByte(tmpCh)
		}
		sb.WriteRune(ch)
	}
	halfCleaned := cleanPath(sb.String())
	halfCleaned = strings.ReplaceAll(halfCleaned, string([]byte{tmpCh}), "")

	return halfCleaned
}

// cleanPath does path.Clean(p) but preserves any trailing slash.
func cleanPath(p string) string {
	cleaned := path.Clean(p)
	if cleaned != "/" && strings.HasSuffix(p, "/") {
		cleaned = cleaned + "/"
	}
	return cleaned
}

// tlsPlaceholderWrapper is a no-op listener wrapper that marks
// where the TLS listener should be in a chain of listener wrappers.
// It should only be used if another listener wrapper must be placed
// in front of the TLS handshake.
type tlsPlaceholderWrapper struct{}

func (tlsPlaceholderWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.tls",
		New: func() caddy.Module { return new(tlsPlaceholderWrapper) },
	}
}

func (tlsPlaceholderWrapper) WrapListener(ln net.Listener) net.Listener { return ln }

func (tlsPlaceholderWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

const (
	// DefaultHTTPPort is the default port for HTTP.
	DefaultHTTPPort = 80

	// DefaultHTTPSPort is the default port for HTTPS.
	DefaultHTTPSPort = 443
)

const separator = string(filepath.Separator)

// Interface guard
var (
	_ caddy.ListenerWrapper = (*tlsPlaceholderWrapper)(nil)
	_ caddyfile.Unmarshaler = (*tlsPlaceholderWrapper)(nil)
)
