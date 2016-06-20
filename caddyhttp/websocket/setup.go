package websocket

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
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
		cmd, args, err := caddy.SplitCommandAndArgs(command)
		if err != nil {
			return nil, err
		}

		websocks = append(websocks, Config{
			Path:      path,
			Command:   cmd,
			Arguments: args,
			Respawn:   respawn, // TODO: This isn't used currently
		})
	}

	return websocks, nil

}
