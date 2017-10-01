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

package timeouts

import (
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("timeouts", caddy.Plugin{
		ServerType: "http",
		Action:     setupTimeouts,
	})
}

func setupTimeouts(c *caddy.Controller) error {
	config := httpserver.GetConfig(c)

	for c.Next() {
		var hasOptionalBlock bool
		for c.NextBlock() {
			hasOptionalBlock = true

			// ensure the kind of timeout is recognized
			kind := c.Val()
			if kind != "read" && kind != "header" && kind != "write" && kind != "idle" {
				return c.Errf("unknown timeout '%s': must be read, header, write, or idle", kind)
			}

			// parse the timeout duration
			if !c.NextArg() {
				return c.ArgErr()
			}
			if c.NextArg() {
				// only one value permitted
				return c.ArgErr()
			}
			var dur time.Duration
			if c.Val() != "none" {
				var err error
				dur, err = time.ParseDuration(c.Val())
				if err != nil {
					return c.Errf("%v", err)
				}
				if dur < 0 {
					return c.Err("non-negative duration required for timeout value")
				}
			}

			// set this timeout's duration
			switch kind {
			case "read":
				config.Timeouts.ReadTimeout = dur
				config.Timeouts.ReadTimeoutSet = true
			case "header":
				config.Timeouts.ReadHeaderTimeout = dur
				config.Timeouts.ReadHeaderTimeoutSet = true
			case "write":
				config.Timeouts.WriteTimeout = dur
				config.Timeouts.WriteTimeoutSet = true
			case "idle":
				config.Timeouts.IdleTimeout = dur
				config.Timeouts.IdleTimeoutSet = true
			}
		}
		if !hasOptionalBlock {
			// set all timeouts to the same value

			if !c.NextArg() {
				return c.ArgErr()
			}
			if c.NextArg() {
				// only one value permitted
				return c.ArgErr()
			}
			val := c.Val()

			config.Timeouts.ReadTimeoutSet = true
			config.Timeouts.ReadHeaderTimeoutSet = true
			config.Timeouts.WriteTimeoutSet = true
			config.Timeouts.IdleTimeoutSet = true

			if val == "none" {
				config.Timeouts.ReadTimeout = 0
				config.Timeouts.ReadHeaderTimeout = 0
				config.Timeouts.WriteTimeout = 0
				config.Timeouts.IdleTimeout = 0
			} else {
				dur, err := time.ParseDuration(val)
				if err != nil {
					return c.Errf("unknown timeout duration: %v", err)
				}
				if dur < 0 {
					return c.Err("non-negative duration required for timeout value")
				}
				config.Timeouts.ReadTimeout = dur
				config.Timeouts.ReadHeaderTimeout = dur
				config.Timeouts.WriteTimeout = dur
				config.Timeouts.IdleTimeout = dur
			}
		}
	}

	return nil
}
