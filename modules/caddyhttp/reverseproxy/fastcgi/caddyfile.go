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

package fastcgi

import "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

// UnmarshalCaddyfile deserializes Caddyfile tokens into h.
//
//     transport fastcgi {
//         root <path>
//         split <at>
//         env <key> <value>
//     }
//
func (t *Transport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.NextBlock() {
		switch d.Val() {
		case "root":
			if !d.NextArg() {
				return d.ArgErr()
			}
			t.Root = d.Val()

		case "split":
			if !d.NextArg() {
				return d.ArgErr()
			}
			t.SplitPath = d.Val()

		case "env":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.ArgErr()
			}
			if t.EnvVars == nil {
				t.EnvVars = make(map[string]string)
			}
			t.EnvVars[args[0]] = args[1]

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}
	return nil
}
