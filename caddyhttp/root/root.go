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

package root

import (
	"log"
	"os"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("root", caddy.Plugin{
		ServerType: "http",
		Action:     setupRoot,
	})
}

func setupRoot(c *caddy.Controller) error {
	config := httpserver.GetConfig(c)

	for c.Next() {
		if !c.NextArg() {
			return c.ArgErr()
		}
		config.Root = c.Val()
		if c.NextArg() {
			// only one argument allowed
			return c.ArgErr()
		}
	}
	//first check that the path is not a symlink, os.Stat panics when this is true
	info, _ := os.Lstat(config.Root)
	if info != nil && info.Mode()&os.ModeSymlink == os.ModeSymlink {
		//just print out info, delegate responsibility for symlink validity to
		//underlying Go framework, no need to test / verify twice
		log.Printf("[INFO] Root path is symlink: %s", config.Root)
	} else {
		// Check if root path exists
		_, err := os.Stat(config.Root)
		if err != nil {
			if os.IsNotExist(err) {
				// Allow this, because the folder might appear later.
				// But make sure the user knows!
				log.Printf("[WARNING] Root path does not exist: %s", config.Root)
			} else {
				return c.Errf("Unable to access root path '%s': %v", config.Root, err)
			}
		}
	}

	return nil
}
