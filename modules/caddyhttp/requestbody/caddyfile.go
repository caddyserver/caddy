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
	"strconv"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("request_body", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name

	rb := new(RequestBody)

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

		case "read_timeout":
			var timeoutStr string
			if !h.AllArgs(&timeoutStr) {
				return nil, h.ArgErr()
			}
			timeout, err := time.ParseDuration(timeoutStr)
			if err != nil {
				return nil, h.Errf("parsing read_timeout: %v", err)
			}
			rb.ReadTimeout = timeout

		case "read_min_rate":
			var rateStr string
			if !h.AllArgs(&rateStr) {
				return nil, h.ArgErr()
			}
			rate, err := strconv.ParseInt(rateStr, 10, 64)
			if err != nil {
				return nil, h.Errf("parsing read_min_rate: %v", err)
			}
			rb.ReadMinRate = rate

		case "write_timeout":
			var timeoutStr string
			if !h.AllArgs(&timeoutStr) {
				return nil, h.ArgErr()
			}
			timeout, err := time.ParseDuration(timeoutStr)
			if err != nil {
				return nil, h.Errf("parsing write_timeout: %v", err)
			}
			rb.WriteTimeout = timeout

		case "write_min_rate":
			var rateStr string
			if !h.AllArgs(&rateStr) {
				return nil, h.ArgErr()
			}
			rate, err := strconv.ParseInt(rateStr, 10, 64)
			if err != nil {
				return nil, h.Errf("parsing write_min_rate: %v", err)
			}
			rb.WriteMinRate = rate

		case "max_write_chunk":
			var sizeStr string
			if !h.AllArgs(&sizeStr) {
				return nil, h.ArgErr()
			}
			size, err := humanize.ParseBytes(sizeStr)
			if err != nil {
				return nil, h.Errf("parsing max_write_chunk: %v", err)
			}
			rb.MaxWriteChunk = int(size)

		case "set":
			var setStr string
			if !h.AllArgs(&setStr) {
				return nil, h.ArgErr()
			}
			rb.Set = setStr
		default:
			return nil, h.Errf("unrecognized request_body subdirective '%s'", h.Val())
		}
	}

	return rb, nil
}
