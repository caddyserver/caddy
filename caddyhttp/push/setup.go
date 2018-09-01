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

package push

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("push", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

var errInvalidHeader = errors.New("header directive requires [name] [value]")

var errHeaderStartsWithColon = errors.New("header cannot start with colon")
var errMethodNotSupported = errors.New("push supports only GET and HEAD methods")

const pushHeader = "X-Push"

var emptyRules = []Rule{}

// setup configures a new Push middleware
func setup(c *caddy.Controller) error {
	rules, err := parsePushRules(c)

	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)
	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Middleware{Next: next, Rules: rules, Root: http.Dir(cfg.Root), indexPages: cfg.IndexPages}
	})

	return nil
}

func parsePushRules(c *caddy.Controller) ([]Rule, error) {
	var rules = make(map[string]*Rule)

	for c.NextLine() {
		var rule *Rule
		var resources []Resource
		var ops []ruleOp

		parseBlock := func() error {
			for c.NextBlock() {
				val := c.Val()

				switch val {
				case "method":
					if !c.NextArg() {
						return c.ArgErr()
					}

					method := c.Val()

					if err := validateMethod(method); err != nil {
						return errMethodNotSupported
					}

					ops = append(ops, setMethodOp(method))

				case "header":
					args := c.RemainingArgs()

					if len(args) != 2 {
						return errInvalidHeader
					}

					if err := validateHeader(args[0]); err != nil {
						return err
					}

					ops = append(ops, setHeaderOp(args[0], args[1]))
				default:
					resources = append(resources, Resource{
						Path:   val,
						Method: http.MethodGet,
						Header: http.Header{pushHeader: []string{}},
					})
				}
			}
			return nil
		}

		args := c.RemainingArgs()

		if len(args) == 0 {
			rule = new(Rule)
			rule.Path = "/"
			rules["/"] = rule
			err := parseBlock()
			if err != nil {
				return emptyRules, err
			}
		} else {
			path := args[0]

			if existingRule, ok := rules[path]; ok {
				rule = existingRule
			} else {
				rule = new(Rule)
				rule.Path = path
				rules[rule.Path] = rule
			}

			for i := 1; i < len(args); i++ {
				resources = append(resources, Resource{
					Path:   args[i],
					Method: http.MethodGet,
					Header: http.Header{pushHeader: []string{}},
				})
			}

			err := parseBlock()
			if err != nil {
				return emptyRules, err
			}
		}

		for _, op := range ops {
			op(resources)
		}
		rule.Resources = append(rule.Resources, resources...)
	}

	var returnRules []Rule
	for _, rule := range rules {
		returnRules = append(returnRules, *rule)
	}

	return returnRules, nil
}

func setHeaderOp(key, value string) func(resources []Resource) {
	return func(resources []Resource) {
		for index := range resources {
			resources[index].Header.Set(key, value)
		}
	}
}

func setMethodOp(method string) func(resources []Resource) {
	return func(resources []Resource) {
		for index := range resources {
			resources[index].Method = method
		}
	}
}

func validateHeader(header string) error {
	if strings.HasPrefix(header, ":") {
		return errHeaderStartsWithColon
	}

	switch strings.ToLower(header) {
	case "content-length", "content-encoding", "trailer", "te", "expect", "host":
		return fmt.Errorf("push headers cannot include %s", header)
	}

	return nil
}

// rules based on https://go-review.googlesource.com/#/c/29439/4/http2/go18.go#94
func validateMethod(method string) error {
	if method != http.MethodGet && method != http.MethodHead {
		return errMethodNotSupported
	}

	return nil
}
