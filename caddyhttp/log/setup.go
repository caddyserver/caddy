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

package log

import (
	"net"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// setup sets up the logging middleware.
func setup(c *caddy.Controller) error {
	rules, err := logParse(c)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		for _, entry := range rule.Entries {
			entry.Log.Attach(c)
		}
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Logger{Next: next, Rules: rules, ErrorFunc: httpserver.DefaultErrorFunc}
	})

	return nil
}

func logParse(c *caddy.Controller) ([]*Rule, error) {
	var rules []*Rule

	for c.Next() {
		args := c.RemainingArgs()

		ip4Mask := net.IPMask(net.ParseIP(DefaultIP4Mask).To4())
		ip6Mask := net.IPMask(net.ParseIP(DefaultIP6Mask))
		ipMaskExists := false

		var logRoller *httpserver.LogRoller
		logRoller = httpserver.DefaultLogRoller()

		for c.NextBlock() {
			what := c.Val()
			where := c.RemainingArgs()

			if what == "ipmask" {

				if len(where) == 0 {
					return nil, c.ArgErr()
				}

				if where[0] != "" {
					ip4MaskStr := where[0]
					ipv4 := net.ParseIP(ip4MaskStr).To4()

					if ipv4 == nil {
						return nil, c.Err("IPv4 Mask not valid IP Mask Format")
					} else {
						ip4Mask = net.IPMask(ipv4)
						ipMaskExists = true
					}
				}

				if len(where) > 1 {

					ip6MaskStr := where[1]
					ipv6 := net.ParseIP(ip6MaskStr)

					if ipv6 == nil {
						return nil, c.Err("IPv6 Mask not valid IP Mask Format")
					} else {
						ip6Mask = net.IPMask(ipv6)
						ipMaskExists = true
					}

				}

			} else if httpserver.IsLogRollerSubdirective(what) {

				if err := httpserver.ParseRoller(logRoller, what, where...); err != nil {
					return nil, err
				}

			} else {
				return nil, c.ArgErr()
			}

		}

		path := "/"
		format := DefaultLogFormat
		output := DefaultLogFilename

		switch len(args) {
		case 0:
			// nothing to change
		case 1:
			// Only an output file specified
			output = args[0]
		case 2, 3:
			// Path scope, output file, and maybe a format specified
			path = args[0]
			output = args[1]
			if len(args) > 2 {
				format = strings.Replace(args[2], "{common}", CommonLogFormat, -1)
				format = strings.Replace(format, "{combined}", CombinedLogFormat, -1)
			}
		default:
			// Maximum number of args in log directive is 3.
			return nil, c.ArgErr()
		}

		rules = appendEntry(rules, path, &Entry{
			Log: &httpserver.Logger{
				Output:       output,
				Roller:       logRoller,
				V4ipMask:     ip4Mask,
				V6ipMask:     ip6Mask,
				IPMaskExists: ipMaskExists,
			},
			Format: format,
		})
	}

	return rules, nil
}

func appendEntry(rules []*Rule, pathScope string, entry *Entry) []*Rule {
	for _, rule := range rules {
		if rule.PathScope == pathScope {
			rule.Entries = append(rule.Entries, entry)
			return rules
		}
	}

	rules = append(rules, &Rule{
		PathScope: pathScope,
		Entries:   []*Entry{entry},
	})

	return rules
}

const (
	// IP Masks that have no effect on IP Address
	DefaultIP4Mask = "255.255.255.255"

	DefaultIP6Mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
)
