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

package websocket

import (
	"strconv"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("websocket", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new WebSocket middleware instance.
func setup(c *caddy.Controller) error {
	websocks, err := webSocketParse(c)
	if err != nil {
		return err
	}

	GatewayInterface = caddy.AppName + "-CGI/1.1"
	ServerSoftware = caddy.AppName + "/" + caddy.AppVersion

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return WebSocket{Next: next, Sockets: websocks}
	})

	return nil
}

func webSocketParse(c *caddy.Controller) ([]Config, error) {
	var websocks []Config

	for c.Next() {
		var respawn bool
		var wsType string
		var bufSize int

		optionalBlock := func() (hadBlock bool, err error) {
			for c.NextBlock() {
				hadBlock = true
				if c.Val() == "respawn" {
					respawn = true
				} else if c.Val() == "type" {
					arg := c.RemainingArgs()
					if len(arg) > 0 {
						wsType = arg[0]
					}
				} else if c.Val() == "bufsize" {
					arg := c.RemainingArgs()
					if len(arg) > 0 {
						var err error
						bufSize, err = strconv.Atoi(arg[0])
						if (bufSize < 0) || (err != nil) {
							bufSize = 0
						}
					}
				} else {
					return true, c.Err("Expected websocket configuration parameter in block")
				}
			}
			return
		}

		var val, path, command string

		// Path or command; not sure which yet
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		val = c.Val()

		// Extra configuration may be in a block
		hadBlock, err := optionalBlock()
		if err != nil {
			return nil, err
		}

		if !hadBlock {
			// The next argument on this line will be the command or an open curly brace
			if c.NextArg() {
				path = val
				command = c.Val()
			} else {
				path = "/"
				command = val
			}

			// Okay, check again for optional block
			_, err = optionalBlock()
			if err != nil {
				return nil, err
			}
		}

		// Split command into the actual command and its arguments
		cmd, args, err := caddy.SplitCommandAndArgs(command)
		if err != nil {
			return nil, err
		}

		if wsType == "" {
			wsType = "lines"
		}

		websocks = append(websocks, Config{
			Path:      path,
			Command:   cmd,
			Arguments: args,
			Respawn:   respawn, // TODO: This isn't used currently
			Type:      wsType,
			BufSize:   bufSize,
		})
	}

	return websocks, nil

}
