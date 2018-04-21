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

package bind

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("bind", caddy.Plugin{
		ServerType: "http",
		Action:     setupBind,
	})
}

func setupBind(c *caddy.Controller) error {
	config := httpserver.GetConfig(c)
	for c.Next() {
		args := c.RemainingArgs()

		if len(args) == 0 {
			return c.Errf("Expected at least one address")
		}

		for _, addr := range args {
			config.ListenHosts = append(config.ListenHosts, addr)
		}

		config.TLS.ListenHost = config.ListenHosts[0] // necessary for ACME challenges, see issue #309
	}
	return nil
}
