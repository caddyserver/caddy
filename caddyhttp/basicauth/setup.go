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

package basicauth

import (
	"net"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("basicauth", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new BasicAuth middleware instance.
func setup(c *caddy.Controller) error {
	cfg := httpserver.GetConfig(c)
	root := cfg.Root

	rules, err := basicAuthParse(c)
	if err != nil {
		return err
	}

	basic := BasicAuth{Rules: rules}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		basic.Next = next
		basic.SiteRoot = root
		return basic
	})

	return nil
}

func basicAuthParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule
	cfg := httpserver.GetConfig(c)

	var err error
	for c.Next() {
		var rule Rule

		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			rule.Username = args[0]
			if rule.Password, err = passwordMatcher(rule.Username, args[1], cfg.Root); err != nil {
				return rules, c.Errf("Get password matcher from %s: %v", c.Val(), err)
			}
		case 3:
			rule.Resources = append(rule.Resources, args[0])
			rule.Username = args[1]
			if rule.Password, err = passwordMatcher(rule.Username, args[2], cfg.Root); err != nil {
				return rules, c.Errf("Get password matcher from %s: %v", c.Val(), err)
			}
		default:
			return rules, c.ArgErr()
		}

		// If nested block is present, process it here
		for c.NextBlock() {
			val := c.Val()
			args = c.RemainingArgs()
			switch len(args) {
			case 0:
				if strings.Contains(val, "/") {
					// Assume single argument is path resource
					rule.Resources = append(rule.Resources, val)
				} else {
					return rules, c.Errf("expected ressource starting with '/', got %q", val)
				}
			case 1:
				switch val {
				case "realm":
					if rule.Realm == "" {
						rule.Realm = strings.Replace(args[0], `"`, `\"`, -1)
					} else {
						return rules, c.Errf("\"realm\" subdirective can only be specified once")
					}
				case "allowed_cidr":
					var network *net.IPNet
					if strings.Contains(args[0], "/") {
						var err error
						_, network, err = net.ParseCIDR(args[0])
						if err != nil {
							return rules, c.Errf("\"allowed_cidr\" failed to parse network %q: %q", args[0], err)
						}
					} else {
						// This is an IP without network explicitly defined
						ip := net.ParseIP(args[0])
						if ip == nil {
							return rules, c.Errf("\"allowed_cidr\" failed to parse ip %q", args[0])
						}
						bits := 128
						if ip.To4() != nil {
							bits = 32
						}
						network = &net.IPNet{
							IP:   ip,
							Mask: net.CIDRMask(bits, bits),
						}
					}

					if network == nil {
						return rules, c.Errf("\"allowed_cidr\" failed to parse network %q", args[0])
					}

					if rule.AllowedCIDR == nil {
						rule.AllowedCIDR = []*net.IPNet{}
					}
					rule.AllowedCIDR = append(rule.AllowedCIDR, network)
				default:
					return rules, c.Errf("expecting \"realm\" or \"allowed_cidr\", got \"%s\"", val)
				}
			default:
				return rules, c.ArgErr()
			}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func passwordMatcher(username, passw, siteRoot string) (PasswordMatcher, error) {
	htpasswdPrefix := "htpasswd="
	if !strings.HasPrefix(passw, htpasswdPrefix) {
		return PlainMatcher(passw), nil
	}
	return GetHtpasswdMatcher(passw[len(htpasswdPrefix):], username, siteRoot)
}
