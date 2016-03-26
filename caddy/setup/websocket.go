package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/websocket"
)

// WebSocket configures a new WebSocket middleware instance.
func WebSocket(c *Controller) (middleware.Middleware, error) {

	websocks, err := webSocketParse(c)
	if err != nil {
		return nil, err
	}
	websocket.GatewayInterface = c.AppName + "-CGI/1.1"
	websocket.ServerSoftware = c.AppName + "/" + c.AppVersion

	return func(next middleware.Handler) middleware.Handler {
		return websocket.WebSocket{Next: next, Sockets: websocks}
	}, nil
}

func webSocketParse(c *Controller) ([]websocket.Config, error) {
	var websocks []websocket.Config
	var respawn bool

	optionalBlock := func() (hadBlock bool, err error) {
		for c.NextBlock() {
			hadBlock = true
			if c.Val() == "respawn" {
				respawn = true
			} else {
				return true, c.Err("Expected websocket configuration parameter in block")
			}
		}
		return
	}

	for c.Next() {
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
		cmd, args, err := middleware.SplitCommandAndArgs(command)
		if err != nil {
			return nil, err
		}

		websocks = append(websocks, websocket.Config{
			Path:      path,
			Command:   cmd,
			Arguments: args,
			Respawn:   respawn, // TODO: This isn't used currently
		})
	}

	return websocks, nil

}
