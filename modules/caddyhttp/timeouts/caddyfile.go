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

package timeouts

import (
	"strconv"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("timeouts", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name

	t := new(Timeouts)

	// configuration should be in a block
	for h.NextBlock(0) {
		switch h.Val() {
		case "read_timeout":
			args := h.RemainingArgs()
			if len(args) < 1 || len(args) > 2 {
				return nil, h.ArgErr()
			}
			timeout, err := time.ParseDuration(args[0])
			if err != nil {
				return nil, h.Errf("parsing read_timeout: %v", err)
			}
			t.ReadTimeout = timeout
			if len(args) == 2 {
				rate, err := strconv.ParseInt(args[1], 10, 64)
				if err != nil {
					return nil, h.Errf("parsing read_timeout min_rate: %v", err)
				}
				t.ReadMinRate = rate
			}

		case "write_timeout":
			args := h.RemainingArgs()
			if len(args) < 1 || len(args) > 2 {
				return nil, h.ArgErr()
			}
			timeout, err := time.ParseDuration(args[0])
			if err != nil {
				return nil, h.Errf("parsing write_timeout: %v", err)
			}
			t.WriteTimeout = timeout
			if len(args) == 2 {
				rate, err := strconv.ParseInt(args[1], 10, 64)
				if err != nil {
					return nil, h.Errf("parsing write_timeout min_rate: %v", err)
				}
				t.WriteMinRate = rate
			}

		case "max_write_chunk":
			var sizeStr string
			if !h.AllArgs(&sizeStr) {
				return nil, h.ArgErr()
			}
			size, err := humanize.ParseBytes(sizeStr)
			if err != nil {
				return nil, h.Errf("parsing max_write_chunk: %v", err)
			}
			t.MaxWriteChunk = int(size)

		default:
			return nil, h.Errf("unrecognized timeouts subdirective '%s'", h.Val())
		}
	}

	return t, nil
}
