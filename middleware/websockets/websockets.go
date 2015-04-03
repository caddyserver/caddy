// Package websockets implements a WebSocket server by executing
// a command and piping its input and output through the WebSocket
// connection.
package websockets

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
	"golang.org/x/net/websocket"
)

type (
	// WebSockets is a type that holds configuration for the
	// websocket middleware generally, like a list of all the
	// websocket endpoints.
	WebSockets struct {
		// Next is the next HTTP handler in the chain for when the path doesn't match
		Next middleware.Handler

		// Sockets holds all the web socket endpoint configurations
		Sockets []WSConfig
	}

	// WSConfig holds the configuration for a single websocket
	// endpoint which may serve multiple websocket connections.
	WSConfig struct {
		Path      string
		Command   string
		Arguments []string
		Respawn   bool // TODO: Not used, but parser supports it until we decide on it
	}
)

// ServeHTTP converts the HTTP request to a WebSocket connection and serves it up.
func (ws WebSockets) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, sockconfig := range ws.Sockets {
		if middleware.Path(r.URL.Path).Matches(sockconfig.Path) {
			socket := WebSocket{
				WSConfig: sockconfig,
				Request:  r,
			}
			websocket.Handler(socket.Handle).ServeHTTP(w, r)
			return 0, nil
		}
	}

	// Didn't match a websocket path, so pass-thru
	return ws.Next.ServeHTTP(w, r)
}

// New constructs and configures a new websockets middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {
	var websocks []WSConfig
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
			hadBlock, err = optionalBlock()
			if err != nil {
				return nil, err
			}
		}

		// Split command into the actual command and its arguments
		cmd, args, err := middleware.SplitCommandAndArgs(command)
		if err != nil {
			return nil, err
		}

		websocks = append(websocks, WSConfig{
			Path:      path,
			Command:   cmd,
			Arguments: args,
			Respawn:   respawn,
		})
	}

	GatewayInterface = envGatewayInterface
	ServerSoftware = envServerSoftware

	return func(next middleware.Handler) middleware.Handler {
		return WebSockets{Next: next, Sockets: websocks}
	}, nil
}

var (
	// See CGI spec, 4.1.4
	GatewayInterface string

	// See CGI spec, 4.1.17
	ServerSoftware string
)

const (
	envGatewayInterface = "caddy-CGI/1.1"
	envServerSoftware   = "caddy/?.?.?" // TODO
)
