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

package startupshutdown

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/onevent/hook"
)

func init() {
	caddy.RegisterPlugin("startup", caddy.Plugin{Action: Startup})
	caddy.RegisterPlugin("shutdown", caddy.Plugin{Action: Shutdown})
}

// Startup (an alias for 'on startup') registers a startup callback to execute during server start.
func Startup(c *caddy.Controller) error {
	config, err := onParse(c, caddy.InstanceStartupEvent)
	if err != nil {
		return c.ArgErr()
	}

	// Register Event Hooks.
	c.OncePerServerBlock(func() error {
		for _, cfg := range config {
			caddy.RegisterEventHook("on-"+cfg.ID, cfg.Hook)
		}
		return nil
	})

	fmt.Println("NOTICE: Startup directive will be removed in a later version. Please migrate to 'on startup'")

	return nil
}

// Shutdown (an alias for 'on shutdown') registers a shutdown callback to execute during server start.
func Shutdown(c *caddy.Controller) error {
	config, err := onParse(c, caddy.ShutdownEvent)
	if err != nil {
		return c.ArgErr()
	}

	// Register Event Hooks.
	for _, cfg := range config {
		caddy.RegisterEventHook("on-"+cfg.ID, cfg.Hook)
	}

	fmt.Println("NOTICE: Shutdown directive will be removed in a later version. Please migrate to 'on shutdown'")

	return nil
}

func onParse(c *caddy.Controller, event caddy.EventName) ([]*hook.Config, error) {
	var config []*hook.Config

	for c.Next() {
		cfg := new(hook.Config)

		args := c.RemainingArgs()
		if len(args) == 0 {
			return config, c.ArgErr()
		}

		// Configure Event.
		cfg.Event = event

		// Assign an unique ID.
		cfg.ID = uuid.New().String()

		// Extract command and arguments.
		command, args, err := caddy.SplitCommandAndArgs(strings.Join(args, " "))
		if err != nil {
			return config, c.Err(err.Error())
		}

		cfg.Command = command
		cfg.Args = args

		config = append(config, cfg)
	}

	return config, nil
}
