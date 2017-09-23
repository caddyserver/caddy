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

package extensions

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("ext", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new instance of 'extensions' middleware for clean URLs.
func setup(c *caddy.Controller) error {
	cfg := httpserver.GetConfig(c)
	root := cfg.Root

	exts, err := extParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Ext{
			Next:       next,
			Extensions: exts,
			Root:       root,
		}
	})

	return nil
}

// extParse sets up an instance of extension middleware
// from a middleware controller and returns a list of extensions.
func extParse(c *caddy.Controller) ([]string, error) {
	var exts []string

	for c.Next() {
		// At least one extension is required
		if !c.NextArg() {
			return exts, c.ArgErr()
		}
		exts = append(exts, c.Val())

		// Tack on any other extensions that may have been listed
		exts = append(exts, c.RemainingArgs()...)
	}

	return exts, nil
}
