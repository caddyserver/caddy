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

package header

import (
	"net/http"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("header", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Headers middleware instance.
func setup(c *caddy.Controller) error {
	rules, err := headersParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Headers{Next: next, Rules: rules}
	})

	return nil
}

func headersParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule

	for c.NextLine() {
		var head Rule
		head.Headers = http.Header{}
		var isNewPattern bool

		if !c.NextArg() {
			return rules, c.ArgErr()
		}
		pattern := c.Val()

		// See if we already have a definition for this Path pattern...
		for _, h := range rules {
			if h.Path == pattern {
				head = h
				break
			}
		}

		// ...otherwise, this is a new pattern
		if head.Path == "" {
			head.Path = pattern
			isNewPattern = true
		}

		for c.NextBlock() {
			// A block of headers was opened...
			name := c.Val()
			value := ""

			args := c.RemainingArgs()

			if len(args) > 1 {
				return rules, c.ArgErr()
			} else if len(args) == 1 {
				value = args[0]
			}

			head.Headers.Add(name, value)
		}
		if c.NextArg() {
			// ... or single header was defined as an argument instead.

			name := c.Val()
			value := c.Val()

			if c.NextArg() {
				value = c.Val()
			}

			head.Headers.Add(name, value)
		}

		if isNewPattern {
			rules = append(rules, head)
		} else {
			for i := 0; i < len(rules); i++ {
				if rules[i].Path == pattern {
					rules[i] = head
					break
				}
			}
		}
	}

	return rules, nil
}
