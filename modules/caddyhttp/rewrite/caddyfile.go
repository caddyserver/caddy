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

package rewrite

import (
	"github.com/caddyserver/caddy/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/caddyconfig/httpcaddyfile"
)

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     rewrite [<matcher>] <to>
//
// The <to> parameter becomes the new URI.
func (rewr *Rewrite) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		rewr.URI = d.Val()
	}
	return nil
}

// Bucket returns the HTTP Caddyfile handler bucket number.
func (rewr Rewrite) Bucket() int { return 1 }

// Interface guard
var _ httpcaddyfile.HandlerDirective = (*Rewrite)(nil)
