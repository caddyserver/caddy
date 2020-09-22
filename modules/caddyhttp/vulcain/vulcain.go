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

// Package vulcain provides a handler allowing to turn any web API
// in a one supporting the Vulcain protocol: https://vulcain.org
//
// COMPATIBILITY NOTE: This module is still experimental and is not
// subject to Caddy's compatibility guarantee.
package vulcain

import (
	"bytes"
	"net/http"
	"strconv"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dunglas/vulcain"
)

func init() {
	caddy.RegisterModule(Vulcain{})
	httpcaddyfile.RegisterHandlerDirective("vulcain", parseCaddyfile)
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

type Vulcain struct {
	OpenAPIFile string `json:"openapi_file,omitempty"`
	MaxPushes   int    `json:"max_pushes,omitempty"`

	vulcain *vulcain.Vulcain
}

// CaddyModule returns the Caddy module information.
func (Vulcain) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.vulcain",
		New: func() caddy.Module { return new(Vulcain) },
	}
}

func (v *Vulcain) Provision(ctx caddy.Context) error {
	if v.MaxPushes == 0 {
		v.MaxPushes = -1
	}

	v.vulcain = vulcain.New(
		vulcain.WithOpenAPIFile(v.OpenAPIFile),
		vulcain.WithMaxPushes(v.MaxPushes),
		vulcain.WithLogger(ctx.Logger(v)),
	)

	return nil
}

// ServeHTTP applies Vulcain directives.
func (v Vulcain) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	rec := caddyhttp.NewResponseRecorder(w, buf, func(status int, header http.Header) bool {
		return v.vulcain.CanApply(w, r, status, header)
	})
	if err := next.ServeHTTP(rec, r); err != nil {
		return err
	}
	if !rec.Buffered() {
		return nil
	}

	b, err := v.vulcain.Apply(r, w, rec.Buffer(), rec.Header())
	if err != nil {
		return rec.WriteResponse()
	}

	w.WriteHeader(rec.Status())
	_, err = w.Write(b)

	return err
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     vulcain {
//         # path to the OpenAPI file describing the relations (for non-hypermedia APIs)
//	       openapi_file <path>
//         # Maximum number of pushes to do (-1 for unlimited)
//         max_pushes -1
//     }
func (v *Vulcain) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "openapi_file":
				if !d.NextArg() {
					return d.ArgErr()
				}

				v.OpenAPIFile = d.Val()

			case "max_pushes":
				if !d.NextArg() {
					return d.ArgErr()
				}

				maxPushes, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("bad max_pushes value '%s': %v", d.Val(), err)
				}

				v.MaxPushes = maxPushes
			}
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Vulcain
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Vulcain)(nil)
	_ caddyhttp.MiddlewareHandler = (*Vulcain)(nil)
	_ caddyfile.Unmarshaler       = (*Vulcain)(nil)
)
