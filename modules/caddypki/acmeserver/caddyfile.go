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

package acmeserver

import (
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("acme_server", parseACMEServer)
}

// parseACMEServer sets up an ACME server handler from Caddyfile tokens.
func parseACMEServer(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	as := new(Handler)
	err := as.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return as, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens
//
//		acme_server [<matcher>] {
//			[no_memory_map]
//			[use_badger_v2]
//		}
//
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			subdirective := d.Val()
			switch subdirective {
			case "no_memory_map":
				h.NoMemoryMap = true
			case "use_badger_v2":
				h.UseBadgerV2 = true
			default:
				return fmt.Errorf("unsupported subdirective %s", subdirective)
			}
		}
	}

	return nil
}
