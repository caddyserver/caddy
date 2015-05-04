package websockets

import (
	"net"
	"net/http"
	"os/exec"
	"strings"

	"golang.org/x/net/websocket"
)

// WebSocket represents a web socket server instance. A WebSocket
// is instantiated for each new websocket request/connection.
type WebSocket struct {
	Config
	*http.Request
}

// Handle handles a WebSocket connection. It launches the
// specified command and streams input and output through
// the command's stdin and stdout.
func (ws WebSocket) Handle(conn *websocket.Conn) {
	cmd := exec.Command(ws.Command, ws.Arguments...)

	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn // TODO: Make this configurable from the Caddyfile

	metavars, err := ws.buildEnv(cmd.Path)
	if err != nil {
		panic(err) // TODO
	}

	cmd.Env = metavars

	err = cmd.Run()
	if err != nil {
		panic(err)
	}
}

// buildEnv creates the meta-variables for the child process according
// to the CGI 1.1 specification: http://tools.ietf.org/html/rfc3875#section-4.1
// cmdPath should be the path of the command being run.
// The returned string slice can be set to the command's Env property.
func (ws WebSocket) buildEnv(cmdPath string) (metavars []string, err error) {
	remoteHost, remotePort, err := net.SplitHostPort(ws.RemoteAddr)
	if err != nil {
		return
	}

	serverHost, serverPort, err := net.SplitHostPort(ws.Host)
	if err != nil {
		return
	}

	metavars = []string{
		`AUTH_TYPE=`,      // Not used
		`CONTENT_LENGTH=`, // Not used
		`CONTENT_TYPE=`,   // Not used
		`GATEWAY_INTERFACE=` + GatewayInterface,
		`PATH_INFO=`,       // TODO
		`PATH_TRANSLATED=`, // TODO
		`QUERY_STRING=` + ws.URL.RawQuery,
		`REMOTE_ADDR=` + remoteHost,
		`REMOTE_HOST=` + remoteHost, // Host lookups are slow - don't do them
		`REMOTE_IDENT=`,             // Not used
		`REMOTE_PORT=` + remotePort,
		`REMOTE_USER=`, // Not used,
		`REQUEST_METHOD=` + ws.Method,
		`REQUEST_URI=` + ws.RequestURI,
		`SCRIPT_NAME=` + cmdPath, // path of the program being executed
		`SERVER_NAME=` + serverHost,
		`SERVER_PORT=` + serverPort,
		`SERVER_PROTOCOL=` + ws.Proto,
		`SERVER_SOFTWARE=` + ServerSoftware,
	}

	// Add each HTTP header to the environment as well
	for header, values := range ws.Header {
		value := strings.Join(values, ", ")
		header = strings.ToUpper(header)
		header = strings.Replace(header, "-", "_", -1)
		value = strings.Replace(value, "\n", " ", -1)
		metavars = append(metavars, "HTTP_"+header+"="+value)
	}

	return
}
