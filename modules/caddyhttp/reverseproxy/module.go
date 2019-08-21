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

package reverseproxy

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(new(LoadBalanced))
	httpcaddyfile.RegisterHandlerDirective("reverse_proxy", parseCaddyfile) // TODO: "proxy"?
}

// CaddyModule returns the Caddy module information.
func (*LoadBalanced) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.reverse_proxy",
		New:  func() caddy.Module { return new(LoadBalanced) },
	}
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     proxy [<matcher>] <to>
//
// TODO: This needs to be finished. It definitely needs to be able to open a block...
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	lb := new(LoadBalanced)
	for h.Next() {
		allTo := h.RemainingArgs()
		if len(allTo) == 0 {
			return nil, h.ArgErr()
		}
		for _, to := range allTo {
			lb.Upstreams = append(lb.Upstreams, &UpstreamConfig{Host: to})
		}
	}
	return lb, nil
}
