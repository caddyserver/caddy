// Package websocket implements a WebSocket server by executing
// a command and piping its input and output through the WebSocket
// connection.
package websocket

import (
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mholt/caddy/middleware"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 1024 * 1024 * 10 // 10 MB default.
)

var (
	// GatewayInterface is the dialect of CGI being used by the server
	// to communicate with the script.  See CGI spec, 4.1.4
	GatewayInterface string

	// ServerSoftware is the name and version of the information server
	// software making the CGI request.  See CGI spec, 4.1.17
	ServerSoftware string
)

type (
	// WebSocket is a type that holds configuration for the
	// websocket middleware generally, like a list of all the
	// websocket endpoints.
	WebSocket struct {
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
func (ws WebSocket) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, sockconfig := range ws.Sockets {
		if middleware.Path(r.URL.Path).Matches(sockconfig.Path) {
			return serveWS(w, r, &sockconfig)
		}
	}

	// Didn't match a websocket path, so pass-thru
	return ws.Next.ServeHTTP(w, r)
}

// serveWS is used for setting and upgrading the HTTP connection to a websocket connection.
// It also spawns the child process that is associated with matched HTTP path/url.
func serveWS(w http.ResponseWriter, r *http.Request, config *Config) (int, error) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return http.StatusBadRequest, err
	}
	defer conn.Close()

	cmd := exec.Command(config.Command, config.Arguments...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return http.StatusBadGateway, err
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return http.StatusBadGateway, err
	}

	metavars, err := buildEnv(cmd.Path, r)
	if err != nil {
		return http.StatusBadGateway, err
	}

	cmd.Env = metavars

	if err := cmd.Start(); err != nil {
		return http.StatusBadGateway, err
	}

	reader(conn, stdout, stdin)

	return 0, nil
}

// buildEnv creates the meta-variables for the child process according
// to the CGI 1.1 specification: http://tools.ietf.org/html/rfc3875#section-4.1
// cmdPath should be the path of the command being run.
// The returned string slice can be set to the command's Env property.
func buildEnv(cmdPath string, r *http.Request) (metavars []string, err error) {
	remoteHost, remotePort, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return
	}

	serverHost, serverPort, err := net.SplitHostPort(r.Host)
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
		`QUERY_STRING=` + r.URL.RawQuery,
		`REMOTE_ADDR=` + remoteHost,
		`REMOTE_HOST=` + remoteHost, // Host lookups are slow - don't do them
		`REMOTE_IDENT=`,             // Not used
		`REMOTE_PORT=` + remotePort,
		`REMOTE_USER=`, // Not used,
		`REQUEST_METHOD=` + r.Method,
		`REQUEST_URI=` + r.RequestURI,
		`SCRIPT_NAME=` + cmdPath, // path of the program being executed
		`SERVER_NAME=` + serverHost,
		`SERVER_PORT=` + serverPort,
		`SERVER_PROTOCOL=` + r.Proto,
		`SERVER_SOFTWARE=` + ServerSoftware,
	}

	// Add each HTTP header to the environment as well
	for header, values := range r.Header {
		value := strings.Join(values, ", ")
		header = strings.ToUpper(header)
		header = strings.Replace(header, "-", "_", -1)
		value = strings.Replace(value, "\n", " ", -1)
		metavars = append(metavars, "HTTP_"+header+"="+value)
	}

	return
}

// reader is the guts of this package. It takes the stdin and stdout pipes
// of the cmd we created in ServeWS and pipes them between the client and server
// over websockets.
func reader(conn *websocket.Conn, stdout io.ReadCloser, stdin io.WriteCloser) {
	// Setup our connection's websocket ping/pong handlers from our const values.
	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	tickerChan := make(chan bool)
	defer func() { tickerChan <- true }() // make sure to close the ticker when we are done.
	go ticker(conn, tickerChan)

	for {
		msgType, r, err := conn.NextReader()
		if err != nil {
			if msgType == -1 {
				return // we got a disconnect from the client. We are good to close.
			}
			conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""), time.Time{})
			return
		}

		w, err := conn.NextWriter(msgType)
		if err != nil {
			conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""), time.Time{})
			return
		}

		if _, err := io.Copy(stdin, r); err != nil {
			conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""), time.Time{})
			return
		}

		go func() {
			if _, err := io.Copy(w, stdout); err != nil {
				conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""), time.Time{})
				return
			}
			if err := w.Close(); err != nil {
				conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""), time.Time{})
				return
			}
		}()
	}
}

// ticker is start by the reader. Basically it is the method that simulates the websocket
// between the server and client to keep it alive with ping messages.
func ticker(conn *websocket.Conn, c chan bool) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		close(c)
	}()

	for { // blocking loop with select to wait for stimulation.
		select {
		case <-ticker.C:
			conn.WriteMessage(websocket.PingMessage, nil)
		case <-c:
			return // clean up this routine.
		}
	}
}
