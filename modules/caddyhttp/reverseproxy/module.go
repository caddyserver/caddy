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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2"
)

// Register caddy module.
func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.reverse_proxy",
		New:  func() interface{} { return new(LoadBalanced) },
	})
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     proxy [<matcher>] <to>
//
// TODO: This needs to be finished. It definitely needs to be able to open a block...
func (lb *LoadBalanced) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		allTo := d.RemainingArgs()
		if len(allTo) == 0 {
			return d.ArgErr()
		}
		for _, to := range allTo {
			lb.Upstreams = append(lb.Upstreams, &UpstreamConfig{Host: to})
		}
	}
	return nil
}

// Bucket returns the HTTP Caddyfile handler bucket number.
func (*LoadBalanced) Bucket() int { return 7 }

// Interface guard
var _ httpcaddyfile.HandlerDirective = (*LoadBalanced)(nil)
