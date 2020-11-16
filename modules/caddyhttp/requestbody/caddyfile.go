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
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dustin/go-humanize"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("request_body", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	rb := new(RequestBody)

	for h.Next() {
		// configuration should be in a block
		for h.NextBlock(0) {
			switch h.Val() {
			case "max_size":
				var sizeStr string
				if !h.AllArgs(&sizeStr) {
					return nil, h.ArgErr()
				}
				size, err := humanize.ParseBytes(sizeStr)
				if err != nil {
					return nil, h.Errf("parsing max_size: %v", err)
				}
				rb.MaxSize = int64(size)
			default:
				return nil, h.Errf("unrecognized servers option '%s'", h.Val())
			}
		}
	}

	return rb, nil
}
