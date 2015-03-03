// Package websockets implements a WebSocket server by executing
// a command and piping its input and output through the WebSocket
// connection.
package websockets

import (
	"log"
	"net/http"

	"github.com/flynn/go-shlex"
	"github.com/mholt/caddy/middleware"
	"golang.org/x/net/websocket"
)

// WebSockets is a type which holds configuration
// for the websocket middleware collectively.
type WebSockets struct {
	Sockets []WebSocket
}

// ServeHTTP more or less converts the HTTP request to a WebSocket connection.
func (ws WebSockets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, socket := range ws.Sockets {
		if middleware.Path(r.URL.Path).Matches(socket.Path) {
			websocket.Handler(socket.Handle).ServeHTTP(w, r)
			return
		}
	}
}

// New constructs and configures a new websockets middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {
	var websocks []WebSocket

	var path string
	var command string

	for c.Next() {
		var val string

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
			log.Fatal("Error parsing command for websocket use: " + err.Error())
		} else if len(parts) == 0 {
			log.Fatal("No command found for use by websocket.")
		}

		cmd = parts[0]
		if len(parts) > 1 {
			args = parts[1:]
		}

		websocks = append(websocks, WebSocket{
			Path:      path,
			Command:   cmd,
			Arguments: args,
		})
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		// We don't use next because websockets aren't HTTP,
		// so we don't invoke other middleware after this.
		return WebSockets{Sockets: websocks}.ServeHTTP
	}, nil
}
