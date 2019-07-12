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
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.request_body",
		New:  func() interface{} { return new(RequestBody) },
	})
}

// RequestBody is a middleware for manipulating the request body.
type RequestBody struct {
	MaxSize int64 `json:"max_size,omitempty"`
}

func (rb RequestBody) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
