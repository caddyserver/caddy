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

package requestbody

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(RequestBody{})
}

// RequestBody is a middleware for manipulating the request body.
type RequestBody struct {
	// The maximum number of bytes to allow reading from the body by a later handler.
	MaxSize int64 `json:"max_size,omitempty"`

	// Overwrites the remote address from which the request came. This is destructive;
	// handlers later in the chain will not be able to recover the true originating
	// address of the request. EXPERIMENTAL: May get changed or removed later.
	RemoteAddress string `json:"remote_address,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (RequestBody) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.request_body",
		New: func() caddy.Module { return new(RequestBody) },
	}
}

func (rb RequestBody) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if rb.RemoteAddress != "" {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		r.RemoteAddr = repl.ReplaceAll(rb.RemoteAddress, "")
	}
	if r.Body == nil {
		return next.ServeHTTP(w, r)
	}
	if rb.MaxSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, rb.MaxSize)
	}
	return next.ServeHTTP(w, r)
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*RequestBody)(nil)
