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
	"strconv"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("request_body", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	rb := new(RequestBody)

	for h.Next() {
		// if not, they should be in a block
		for h.NextBlock(0) {
			field := h.Val()
			if field == "max_size" {
				if h.NextArg() {
					i, err := strconv.Atoi(h.Val())
					if err == nil {
						rb.MaxSize = int64(i)
					}

				}
				continue
			}
		}
	}

	return rb, nil
}
