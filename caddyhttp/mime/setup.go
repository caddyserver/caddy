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

package mime

import (
	"fmt"
	"strings"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("mime", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new mime middleware instance.
func setup(c *caddy.Controller) error {
	configs, err := mimeParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Mime{Next: next, Configs: configs}
	})

	return nil
}

func mimeParse(c *caddy.Controller) (Config, error) {
	configs := Config{}

	for c.Next() {
		// At least one extension is required

		args := c.RemainingArgs()
		switch len(args) {
		case 2:
			if err := validateExt(configs, args[0]); err != nil {
				return configs, err
			}
			configs[args[0]] = args[1]
		case 1:
			return configs, c.ArgErr()
		case 0:
			for c.NextBlock() {
				ext := c.Val()
				if err := validateExt(configs, ext); err != nil {
					return configs, err
				}
				if !c.NextArg() {
					return configs, c.ArgErr()
				}
				configs[ext] = c.Val()
			}
		}

	}

	return configs, nil
}

// validateExt checks for valid file name extension.
func validateExt(configs Config, ext string) error {
	if !strings.HasPrefix(ext, ".") {
		return fmt.Errorf(`mime: invalid extension "%v" (must start with dot)`, ext)
	}
	if _, ok := configs[ext]; ok {
		return fmt.Errorf(`mime: duplicate extension "%v" found`, ext)
	}
	return nil
}
