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

package status

import (
	"strconv"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// init registers Status plugin
func init() {
	caddy.RegisterPlugin("status", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures new Status middleware instance.
func setup(c *caddy.Controller) error {
	rules, err := statusParse(c)
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)
	mid := func(next httpserver.Handler) httpserver.Handler {
		return Status{Rules: rules, Next: next}
	}
	cfg.AddMiddleware(mid)

	return nil
}

// statusParse parses status directive
func statusParse(c *caddy.Controller) ([]httpserver.HandlerConfig, error) {
	var rules []httpserver.HandlerConfig

	for c.Next() {
		hadBlock := false
		args := c.RemainingArgs()

		switch len(args) {
		case 1:
			status, err := strconv.Atoi(args[0])
			if err != nil {
				return rules, c.Errf("Expecting a numeric status code, got '%s'", args[0])
			}

			for c.NextBlock() {
				hadBlock = true
				basePath := c.Val()

				for _, cfg := range rules {
					rule := cfg.(*Rule)
					if rule.Base == basePath {
						return rules, c.Errf("Duplicate path: '%s'", basePath)
					}
				}

				rule := NewRule(basePath, status)
				rules = append(rules, rule)

				if c.NextArg() {
					return rules, c.ArgErr()
				}
			}

			if !hadBlock {
				return rules, c.ArgErr()
			}
		case 2:
			status, err := strconv.Atoi(args[0])
			if err != nil {
				return rules, c.Errf("Expecting a numeric status code, got '%s'", args[0])
			}

			basePath := args[1]
			for _, cfg := range rules {
				rule := cfg.(*Rule)
				if rule.Base == basePath {
					return rules, c.Errf("Duplicate path: '%s'", basePath)
				}
			}

			rule := NewRule(basePath, status)
			rules = append(rules, rule)
		default:
			return rules, c.ArgErr()
		}
	}

	return rules, nil
}
