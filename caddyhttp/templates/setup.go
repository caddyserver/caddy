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

package templates

import (
	"bytes"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("templates", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Templates middleware instance.
func setup(c *caddy.Controller) error {
	rules, err := templatesParse(c)
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)

	tmpls := Templates{
		Rules:   rules,
		Root:    cfg.Root,
		FileSys: http.Dir(cfg.Root),
		BufPool: &sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
	}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		tmpls.Next = next
		return tmpls
	})

	return nil
}

func templatesParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		var rule Rule

		rule.Path = defaultTemplatePath
		rule.Extensions = defaultTemplateExtensions

		args := c.RemainingArgs()

		switch len(args) {
		case 0:
			// Optional block
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return nil, c.ArgErr()
					}
					rule.Path = args[0]

				case "ext":
					args := c.RemainingArgs()
					if len(args) == 0 {
						return nil, c.ArgErr()
					}
					rule.Extensions = args

				case "between":
					args := c.RemainingArgs()
					if len(args) != 2 {
						return nil, c.ArgErr()
					}
					rule.Delims[0] = args[0]
					rule.Delims[1] = args[1]
				}
			}
		default:
			// First argument would be the path
			rule.Path = args[0]

			// Any remaining arguments are extensions
			rule.Extensions = args[1:]
			if len(rule.Extensions) == 0 {
				rule.Extensions = defaultTemplateExtensions
			}
		}

		for _, ext := range rule.Extensions {
			rule.IndexFiles = append(rule.IndexFiles, "index"+ext)
		}

		rules = append(rules, rule)
	}
	return rules, nil
}

const defaultTemplatePath = "/"

var defaultTemplateExtensions = []string{".html", ".htm", ".tmpl", ".tpl", ".txt"}
