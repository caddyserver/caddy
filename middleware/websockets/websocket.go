package websockets

import (
	"net"
	"net/http"
	"os/exec"
	"strings"

	"golang.org/x/net/websocket"
)

// WebSocket represents a web socket server instance. A WebSocket
// struct is instantiated for each new websocket request.
type WebSocket struct {
	WSConfig
	*http.Request
}

// Handle handles a WebSocket connection. It launches the
// specified command and streams input and output through
// the command's stdin and stdout.
func (ws WebSocket) Handle(conn *websocket.Conn) {
	cmd := exec.Command(ws.Command, ws.Arguments...)
	cmd.Stdin = conn
	cmd.Stdout = conn

	err := ws.buildEnv(cmd)
	if err != nil {
		// TODO
	}

	err = cmd.Run()
	if err != nil {
		panic(err)
	}
}

// buildEnv sets the meta-variables for the child process according
// to the CGI 1.1 specification: http://tools.ietf.org/html/rfc3875#section-4.1
func (ws WebSocket) buildEnv(cmd *exec.Cmd) error {
	remoteHost, remotePort, err := net.SplitHostPort(ws.RemoteAddr)
	if err != nil {
		return err
	}
	serverHost, serverPort, err := net.SplitHostPort(ws.Host)
	if err != nil {
		return err
	}

	cmd.Env = []string{
		`AUTH_TYPE=`,      // Not used
		`CONTENT_LENGTH=`, // Not used
		`CONTENT_TYPE=`,   // Not used
		`GATEWAY_INTERFACE=` + gatewayInterface,
		`PATH_INFO=`,       // TODO
		`PATH_TRANSLATED=`, // TODO
		`QUERY_STRING=` + ws.URL.RawQuery,
		`REMOTE_ADDR=` + remoteHost,
		`REMOTE_HOST=` + remoteHost, // TODO (Host lookups are slow; make this configurable)
		`REMOTE_IDENT=`,             // Not used
		`REMOTE_PORT=` + remotePort,
		`REMOTE_USER=`, // Not used,
		`REQUEST_METHOD=` + ws.Method,
		`REQUEST_URI=` + ws.RequestURI,
		`SCRIPT_NAME=`, // TODO - absolute path to program being executed?
		`SERVER_NAME=` + serverHost,
		`SERVER_PORT=` + serverPort,
		`SERVER_PROTOCOL=` + ws.Proto,
		`SERVER_SOFTWARE=` + serverSoftware,
	}

	// Add each HTTP header to the environment as well
	for header, values := range ws.Header {
		value := strings.Join(values, ", ")
		header = strings.ToUpper(header)
		header = strings.Replace(header, "-", "_", -1)
		value = strings.Replace(value, "\n", " ", -1)
		cmd.Env = append(cmd.Env, "HTTP_"+header+"="+value)
	}

	return nil
}

const (
	// See CGI spec, 4.1.4
	gatewayInterface = "caddy-CGI/1.1"

	// See CGI spec, 4.1.17
	serverSoftware = "caddy/0.1.0"
)
