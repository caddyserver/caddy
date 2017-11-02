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

package index

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("index", caddy.Plugin{
		ServerType: "http",
		Action:     setupIndex,
	})
}

func setupIndex(c *caddy.Controller) error {
	var index []string

	cfg := httpserver.GetConfig(c)

	for c.Next() {
		args := c.RemainingArgs()

		if len(args) == 0 {
			return c.Errf("Expected at least one index")
		}

		for _, in := range args {
			index = append(index, in)
		}

		cfg.IndexPages = index
	}

	return nil
}
