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
	weakrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())

	err := caddy.RegisterModule(tlsPlaceholderWrapper{})
	if err != nil {
		caddy.Log().Fatal(err.Error())
	}
}

// RequestMatcher is a type that can match to a request.
// A route matcher MUST NOT modify the request, with the
// only exception being its context.
type RequestMatcher interface {
	Match(*http.Request) bool
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
var emptyHandler Handler = HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })

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

const (
	// DefaultHTTPPort is the default port for HTTP.
	DefaultHTTPPort = 80

	// DefaultHTTPSPort is the default port for HTTPS.
	DefaultHTTPSPort = 443
)

// Interface guard
var _ caddy.ListenerWrapper = (*tlsPlaceholderWrapper)(nil)
