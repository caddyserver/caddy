// Copyright 2015 Light Code Labs, LLC
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

package pprof

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("pprof", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup returns a new instance of a pprof handler. It accepts no arguments or options.
func setup(c *caddy.Controller) error {
	found := false

	for c.Next() {
		if found {
			return c.Err("pprof can only be specified once")
		}
		if len(c.RemainingArgs()) != 0 {
			return c.ArgErr()
		}
		if c.NextBlock() {
			return c.ArgErr()
		}
		found = true
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &Handler{Next: next, Mux: NewMux()}
	})

	return nil
}
