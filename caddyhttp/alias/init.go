// Copyright 2019 Light Code Labs, LLC
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

// Package alias has Middleware that provides a static file server for files in
// folders outside of the global root.
package alias

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("alias", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	for c.Next() {
		// First param is the URL prefix.
		if !c.NextArg() {
			return c.ArgErr()
		}
		url := c.Val()

		// Second parm is a path to use as root when this alias is accessed.
		if !c.NextArg() {
			return c.ArgErr()
		}
		path := c.Val()

		if c.NextArg() {
			// only two arguments allowed.
			return c.ArgErr()
		}

		// Inject our middle ware.
		cfg := httpserver.GetConfig(c)
		mid := func(next httpserver.Handler) httpserver.Handler {
			return NewAliasHandler(
				url,
				path,
				cfg,
				next,
			)
		}
		cfg.AddMiddleware(mid)
	}

	return nil
}
