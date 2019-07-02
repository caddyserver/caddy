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

package rewrite

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("rewrite", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Rewrite middleware instance.
func setup(c *caddy.Controller) error {
	rewrites, err := rewriteParse(c)
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Rewrite{
			Next:    next,
			FileSys: http.Dir(cfg.Root),
			Rules:   rewrites,
		}
	})

	return nil
}

func rewriteParse(c *caddy.Controller) ([]httpserver.HandlerConfig, error) {
	var rules []httpserver.HandlerConfig

	for c.Next() {
		var rule Rule
		var err error
		var base = "/"
		var pattern, to string
		var ext []string
		var negate bool

		args := c.RemainingArgs()

		var matcher httpserver.RequestMatcher

		switch len(args) {
		case 1:
			base = args[0]
			fallthrough
		case 0:
			// Integrate request matcher for 'if' conditions.
			matcher, err = httpserver.SetupIfMatcher(c)
			if err != nil {
				return nil, err
			}

			for c.NextBlock() {
				if httpserver.IfMatcherKeyword(c) {
					continue
				}
				switch c.Val() {
				case "r", "regexp":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					pattern = c.Val()
				case "to":
					args1 := c.RemainingArgs()
					if len(args1) == 0 {
						return nil, c.ArgErr()
					}
					to = strings.Join(args1, " ")
				case "ext":
					args1 := c.RemainingArgs()
					if len(args1) == 0 {
						return nil, c.ArgErr()
					}
					ext = args1
				default:
					return nil, c.ArgErr()
				}
			}
			// ensure to is specified
			if to == "" {
				return nil, c.ArgErr()
			}
			if rule, err = NewComplexRule(base, pattern, to, ext, matcher); err != nil {
				return nil, err
			}
			rules = append(rules, rule)

		// the only unhandled case is 2 and above
		default:
			if args[0] == "not" {
				negate = true
				args = args[1:]
			}
			rule, err = NewSimpleRule(args[0], strings.Join(args[1:], " "), negate)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}

	}

	return rules, nil
}
