package websockets

import (
	"os/exec"

	"golang.org/x/net/websocket"
)

// WebSocket represents a web socket server configuration.
type WebSocket struct {
	Path      string
	Command   string
	Arguments []string
}

// Handle handles a WebSocket connection. It launches the
// specified command and streams input and output through
// the command's stdin and stdout.
func (ws WebSocket) Handle(conn *websocket.Conn) {
	cmd := exec.Command(ws.Command, ws.Arguments...)
	cmd.Stdin = conn
	cmd.Stdout = conn

	// TODO: Set environment variables according to CGI 1.1
	// cf. http://tools.ietf.org/html/rfc3875#section-4.1.4
	cmd.Env = append(cmd.Env, `GATEWAY_INTERFACE="caddy-CGI/1.1"`)

	err := cmd.Run()
	if err != nil {
		panic(err)
	}
}
