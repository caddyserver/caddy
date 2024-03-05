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

package logging

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("log_append", parseCaddyfile)
}

// parseCaddyfile sets up the log_append handler from Caddyfile tokens. Syntax:
//
//	log_append [<matcher>] <key> <value>
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(LogAppend)
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return handler, err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *LogAppend) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if !d.NextArg() {
		return d.ArgErr()
	}
	h.Key = d.Val()
	if !d.NextArg() {
		return d.ArgErr()
	}
	h.Value = d.Val()
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*LogAppend)(nil)
)
