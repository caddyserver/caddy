// Package websockets implements a WebSocket server by executing
// a command and piping its input and output through the WebSocket
// connection.
package websockets

import (
	"errors"
	"net/http"

	"github.com/flynn/go-shlex"
	"github.com/mholt/caddy/middleware"
	"golang.org/x/net/websocket"
)

type (
	// WebSockets is a type that holds configuration for the
	// websocket middleware generally, like a list of all the
	// websocket endpoints.
	WebSockets struct {
		// Sockets holds all the web socket endpoint configurations
		Sockets []WSConfig
	}

	// WSConfig holds the configuration for a single websocket
	// endpoint which may serve zero or more websocket connections.
	WSConfig struct {
		Path      string
		Command   string
		Arguments []string
	}
)

// ServeHTTP converts the HTTP request to a WebSocket connection and serves it up.
func (ws WebSockets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, sockconfig := range ws.Sockets {
		if middleware.Path(r.URL.Path).Matches(sockconfig.Path) {
			socket := WebSocket{
				WSConfig: sockconfig,
				Request:  r,
			}
			websocket.Handler(socket.Handle).ServeHTTP(w, r)
			return
		}
	}
}

// New constructs and configures a new websockets middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {
	var websocks []WSConfig

	for c.Next() {
		var val, path, command string

		// Path or command; not sure which yet
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		val = c.Val()

		// The rest of the arguments are the command
		if c.NextArg() {
			path = val
			command = c.Val()
			for c.NextArg() {
				command += " " + c.Val()
			}
		} else {
			path = "/"
			command = val
		}

		// Split command into the actual command and its arguments
		var cmd string
		var args []string

		parts, err := shlex.Split(command)
		if err != nil {
			return nil, errors.New("Error parsing command for websocket use: " + err.Error())
		} else if len(parts) == 0 {
			return nil, errors.New("No command found for use by websocket")
		}

		cmd = parts[0]
		if len(parts) > 1 {
			args = parts[1:]
		}

		websocks = append(websocks, WSConfig{
			Path:      path,
			Command:   cmd,
			Arguments: args,
		})
	}

	GatewayInterface = envGatewayInterface
	ServerSoftware = envServerSoftware

	return func(next http.HandlerFunc) http.HandlerFunc {
		// We don't use next because websockets aren't HTTP,
		// so we don't invoke other middleware after this.
		return WebSockets{Sockets: websocks}.ServeHTTP
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
	envServerSoftware   = "caddy/0.1.0"
)
