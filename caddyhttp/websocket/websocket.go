// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package websocket implements a WebSocket server by executing
// a command and piping its input and output through the WebSocket
// connection.
package websocket

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/gorilla/websocket"
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
		Next httpserver.Handler

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
		Type      string
		BufSize   int
	}

	wsGetUpgrader interface {
		GetUpgrader() wsUpgrader
	}

	wsUpgrader interface {
		Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (wsConn, error)
	}

	wsConn interface {
		Close() error
		ReadMessage() (messageType int, p []byte, err error)
		SetPongHandler(h func(appData string) error)
		SetReadDeadline(t time.Time) error
		SetReadLimit(limit int64)
		SetWriteDeadline(t time.Time) error
		WriteControl(messageType int, data []byte, deadline time.Time) error
		WriteMessage(messageType int, data []byte) error
	}
)

// ServeHTTP converts the HTTP request to a WebSocket connection and serves it up.
func (ws WebSocket) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, sockConfig := range ws.Sockets {
		if httpserver.Path(r.URL.Path).Matches(sockConfig.Path) {
			return serveWS(w, r, &sockConfig)
		}
	}

	// Didn't match a websocket path, so pass-through
	return ws.Next.ServeHTTP(w, r)
}

// serveWS is used for setting and upgrading the HTTP connection to a websocket connection.
// It also spawns the child process that is associated with matched HTTP path/url.
func serveWS(w http.ResponseWriter, r *http.Request, config *Config) (int, error) {
	gu, castok := w.(wsGetUpgrader)
	var u wsUpgrader
	if gu != nil && castok {
		u = gu.GetUpgrader()
	} else {
		u = &realWsUpgrader{o: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		}}
	}

	conn, err := u.Upgrade(w, r, nil)
	if err != nil {
		// the connection has been "handled" -- WriteHeader was called with Upgrade,
		// so don't return an error status code; just return an error
		return 0, err
	}
	defer conn.Close()

	cmd := exec.Command(config.Command, config.Arguments...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return http.StatusBadGateway, err
	}
	defer stdout.Close()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return http.StatusBadGateway, err
	}
	defer stdin.Close()

	metavars, err := buildEnv(cmd.Path, r)
	if err != nil {
		return http.StatusBadGateway, err
	}

	cmd.Env = metavars

	if err := cmd.Start(); err != nil {
		return http.StatusBadGateway, err
	}

	done := make(chan struct{})
	go pumpStdout(conn, stdout, done, config)
	pumpStdin(conn, stdin, config)

	_ = stdin.Close() // close stdin to end the process

	if err := cmd.Process.Signal(os.Interrupt); err != nil { // signal an interrupt to kill the process
		return http.StatusInternalServerError, err
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		// terminate with extreme prejudice.
		if err := cmd.Process.Signal(os.Kill); err != nil {
			return http.StatusInternalServerError, err
		}
		<-done
	}

	// not sure what we want to do here.
	// status for an "exited" process is greater
	// than 0, but isn't really an error per se.
	// just going to ignore it for now.
	if err := cmd.Wait(); err != nil {
		log.Println("[ERROR] failed to release resources: ", err)
	}

	return 0, nil
}

// buildEnv creates the meta-variables for the child process according
// to the CGI 1.1 specification: http://tools.ietf.org/html/rfc3875#section-4.1
// cmdPath should be the path of the command being run.
// The returned string slice can be set to the command's Env property.
func buildEnv(cmdPath string, r *http.Request) (metavars []string, err error) {
	if !strings.Contains(r.RemoteAddr, ":") {
		r.RemoteAddr += ":"
	}
	remoteHost, remotePort, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return
	}

	if !strings.Contains(r.Host, ":") {
		r.Host += ":"
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

// pumpStdin handles reading data from the websocket connection and writing
// it to stdin of the process.
func pumpStdin(conn wsConn, stdin io.WriteCloser, config *Config) {
	// Setup our connection's websocket ping/pong handlers from our const values.
	defer conn.Close()
	conn.SetReadLimit(maxMessageSize)
	if err := conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		log.Println("[ERROR] failed to set read deadline: ", err)
	}
	conn.SetPongHandler(func(string) error {
		if err := conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
			log.Println("[ERROR] failed to set read deadline: ", err)
		}
		return nil
	})
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if config.Type == "lines" {
			// no '\n' from client, so append '\n' to spawned process
			message = append(message, '\n')
		}
		if _, err := stdin.Write(message); err != nil {
			break
		}
	}
}

// pumpStdout handles reading data from stdout of the process and writing
// it to websocket connection.
func pumpStdout(conn wsConn, stdout io.Reader, done chan struct{}, config *Config) {
	go pinger(conn, done)
	defer func() {
		_ = conn.Close()
		close(done) // make sure to close the pinger when we are done.
	}()

	if config.Type == "lines" {
		// message must end with '\n'
		s := bufio.NewScanner(stdout)
		if config.BufSize > 0 {
			s.Buffer(make([]byte, config.BufSize), config.BufSize)
		}
		for s.Scan() {
			if err := conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Println("[ERROR] failed to set write deadline: ", err)
			}
			if err := conn.WriteMessage(websocket.TextMessage, bytes.TrimSpace(s.Bytes())); err != nil {
				break
			}
		}
		if s.Err() != nil {
			err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, s.Err().Error()), time.Time{})
			if err != nil {
				log.Println("[ERROR] WriteControl failed: ", err)
			}
		}
	} else if config.Type == "text" {
		// handle UTF-8 text message, newline is not required
		r := bufio.NewReader(stdout)
		var err1 error
		var len int
		remainBuf := make([]byte, utf8.UTFMax)
		remainLen := 0
		bufSize := config.BufSize
		if bufSize <= 0 {
			bufSize = 2048
		}
		for {
			out := make([]byte, bufSize)
			copy(out[:remainLen], remainBuf[:remainLen])
			len, err1 = r.Read(out[remainLen:])
			if err1 != nil {
				break
			}
			len += remainLen
			remainLen = findIncompleteRuneLength(out, len)
			if remainLen > 0 {
				remainBuf = out[len-remainLen : len]
			}
			if err := conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Println("[ERROR] failed to set write deadline: ", err)
			}
			if err := conn.WriteMessage(websocket.TextMessage, out[0:len-remainLen]); err != nil {
				break
			}
		}
		if err1 != nil {
			err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, err1.Error()), time.Time{})
			if err != nil {
				log.Println("[ERROR] WriteControl failed: ", err)
			}
		}
	} else if config.Type == "binary" {
		// treat message as binary data
		r := bufio.NewReader(stdout)
		var err1 error
		var len int
		bufSize := config.BufSize
		if bufSize <= 0 {
			bufSize = 2048
		}
		for {
			out := make([]byte, bufSize)
			len, err1 = r.Read(out)
			if err1 != nil {
				break
			}
			if err := conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Println("[ERROR] failed to set write deadline: ", err)
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, out[0:len]); err != nil {
				break
			}
		}
		if err1 != nil {
			err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, err1.Error()), time.Time{})
			if err != nil {
				log.Println("[ERROR] WriteControl failed: ", err)
			}
		}
	}
}

// pinger simulates the websocket to keep it alive with ping messages.
func pinger(conn wsConn, done chan struct{}) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for { // blocking loop with select to wait for stimulation.
		select {
		case <-ticker.C:
			if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
				err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, err.Error()), time.Time{})
				if err != nil {
					log.Println("[ERROR] WriteControl failed: ", err)
				}
				return
			}
		case <-done:
			return // clean up this routine.
		}
	}
}

type realWsUpgrader struct {
	o *websocket.Upgrader
}

type realWsConn struct {
	o *websocket.Conn
}

func (u *realWsUpgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (wsConn, error) {
	a, b := u.o.Upgrade(w, r, responseHeader)
	return &realWsConn{o: a}, b
}

func (c *realWsConn) Close() error {
	return c.o.Close()
}
func (c *realWsConn) ReadMessage() (messageType int, p []byte, err error) {
	return c.o.ReadMessage()
}
func (c *realWsConn) SetPongHandler(h func(appData string) error) {
	c.o.SetPongHandler(h)
}
func (c *realWsConn) SetReadDeadline(t time.Time) error {
	return c.o.SetReadDeadline(t)
}
func (c *realWsConn) SetReadLimit(limit int64) {
	c.o.SetReadLimit(limit)
}
func (c *realWsConn) SetWriteDeadline(t time.Time) error {
	return c.o.SetWriteDeadline(t)
}
func (c *realWsConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	return c.o.WriteControl(messageType, data, deadline)
}
func (c *realWsConn) WriteMessage(messageType int, data []byte) error {
	return c.o.WriteMessage(messageType, data)
}

func findIncompleteRuneLength(p []byte, length int) int {
	if length == 0 {
		return 0
	}
	if rune(p[length-1]) < utf8.RuneSelf {
		// ASCII 7-bit always complete
		return 0
	}

	lowest := length - utf8.UTFMax
	if lowest < 0 {
		lowest = 0
	}
	for start := length - 1; start >= lowest; start-- {
		if (p[start] >> 5) == 0x06 {
			// 2-byte utf-8 start byte
			if length-start >= 2 {
				// enough bytes
				return 0
			}
			// 1 byte outstanding
			return 1
		}

		if (p[start] >> 4) == 0x0E {
			// 3-byte utf-8 start byte
			if length-start >= 3 {
				// enough bytes
				return 0
			}
			// some bytes outstanding
			return length - start
		}

		if (p[start] >> 3) == 0x1E {
			// 4-byte utf-8 start byte
			if length-start >= 4 {
				// enough bytes
				return 0
			}
			// some bytes outstanding
			return length - start
		}
	}

	// No utf-8 start byte
	return 0
}
