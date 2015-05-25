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
		Sockets []Config
	}

	// Config holds the configuration for a single websocket
	// endpoint which may serve multiple websocket connections.
	Config struct {
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
				Config:  sockconfig,
				Request: r,
			}
			websocket.Handler(socket.Handle).ServeHTTP(w, r)
			return 0, nil
		}
	}

	// Didn't match a websocket path, so pass-thru
	return ws.Next.ServeHTTP(w, r)
}

var (
	// GatewayInterface is the dialect of CGI being used by the server
	// to communicate with the script.  See CGI spec, 4.1.4
	GatewayInterface string

	// ServerSoftware is the name and version of the information server
	// software making the CGI request.  See CGI spec, 4.1.17
	ServerSoftware string
)
