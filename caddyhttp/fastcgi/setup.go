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

package fastcgi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

var defaultTimeout = 60 * time.Second

func init() {
	caddy.RegisterPlugin("fastcgi", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new FastCGI middleware instance.
func setup(c *caddy.Controller) error {
	cfg := httpserver.GetConfig(c)

	rules, err := fastcgiParse(c)
	if err != nil {
		return err
	}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Handler{
			Next:            next,
			Rules:           rules,
			Root:            cfg.Root,
			FileSys:         http.Dir(cfg.Root),
			SoftwareName:    caddy.AppName,
			SoftwareVersion: caddy.AppVersion,
			ServerName:      cfg.Addr.Host,
			ServerPort:      cfg.Addr.Port,
		}
	})

	return nil
}

func fastcgiParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule

	cfg := httpserver.GetConfig(c)
	absRoot, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}

	for c.Next() {
		args := c.RemainingArgs()

		if len(args) < 2 || len(args) > 3 {
			return rules, c.ArgErr()
		}

		rule := Rule{
			Root:           absRoot,
			Path:           args[0],
			ConnectTimeout: defaultTimeout,
			ReadTimeout:    defaultTimeout,
			SendTimeout:    defaultTimeout,
		}

		upstreams := []string{args[1]}

		srvUpstream := false
		if strings.HasPrefix(upstreams[0], "srv://") {
			srvUpstream = true
		}

		if len(args) == 3 {
			if err := fastcgiPreset(args[2], &rule); err != nil {
				return rules, err
			}
		}

		var err error

		for c.NextBlock() {
			switch c.Val() {
			case "root":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.Root = c.Val()

			case "ext":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.Ext = c.Val()
			case "split":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.SplitPath = c.Val()
			case "index":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return rules, c.ArgErr()
				}
				rule.IndexFiles = args

			case "upstream":
				if srvUpstream {
					return rules, c.Err("additional upstreams are not supported with SRV upstream")
				}

				args := c.RemainingArgs()

				if len(args) != 1 {
					return rules, c.ArgErr()
				}

				upstreams = append(upstreams, args[0])
			case "env":
				envArgs := c.RemainingArgs()
				if len(envArgs) < 2 {
					return rules, c.ArgErr()
				}
				rule.EnvVars = append(rule.EnvVars, [2]string{envArgs[0], envArgs[1]})
			case "except":
				ignoredPaths := c.RemainingArgs()
				if len(ignoredPaths) == 0 {
					return rules, c.ArgErr()
				}
				rule.IgnoredSubPaths = ignoredPaths

			case "connect_timeout":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.ConnectTimeout, err = time.ParseDuration(c.Val())
				if err != nil {
					return rules, err
				}
			case "read_timeout":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				readTimeout, err := time.ParseDuration(c.Val())
				if err != nil {
					return rules, err
				}
				rule.ReadTimeout = readTimeout
			case "send_timeout":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				sendTimeout, err := time.ParseDuration(c.Val())
				if err != nil {
					return rules, err
				}
				rule.SendTimeout = sendTimeout
			}
		}

		if srvUpstream {
			balancer, err := parseSRV(upstreams[0])
			if err != nil {
				return rules, c.Err("malformed service locator string: " + err.Error())
			}
			rule.balancer = balancer
		} else {
			rule.balancer = &roundRobin{addresses: upstreams, index: -1}
		}

		rules = append(rules, rule)
	}
	return rules, nil
}

func parseSRV(locator string) (*srv, error) {
	if locator[6:] == "" {
		return nil, fmt.Errorf("%s does not include the host", locator)
	}

	return &srv{
		service:  locator[6:],
		resolver: &net.Resolver{},
	}, nil
}

// fastcgiPreset configures rule according to name. It returns an error if
// name is not a recognized preset name.
func fastcgiPreset(name string, rule *Rule) error {
	switch name {
	case "php":
		rule.Ext = ".php"
		rule.SplitPath = ".php"
		rule.IndexFiles = []string{"index.php"}
	default:
		return errors.New(name + " is not a valid preset name")
	}
	return nil
}
