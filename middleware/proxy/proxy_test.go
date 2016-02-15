package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func init() {
	tryDuration = 50 * time.Millisecond // prevent tests from hanging
}

func TestReverseProxy(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	var requestReceived bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.Write([]byte("Hello, client"))
	}))
	defer backend.Close()

	// set up proxy
	p := &Proxy{
		Upstreams: []Upstream{newFakeUpstream(backend.URL, false)},
	}

	// create request and response recorder
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	if !requestReceived {
		t.Error("Expected backend to receive request, but it didn't")
	}
}

func TestReverseProxyInsecureSkipVerify(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	var requestReceived bool
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.Write([]byte("Hello, client"))
	}))
	defer backend.Close()

	// set up proxy
	p := &Proxy{
		Upstreams: []Upstream{newFakeUpstream(backend.URL, true)},
	}

	// create request and response recorder
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	if !requestReceived {
		t.Error("Even with insecure HTTPS, expected backend to receive request, but it didn't")
	}
}

func TestWebSocketReverseProxyServeHTTPHandler(t *testing.T) {
	// No-op websocket backend simply allows the WS connection to be
	// accepted then it will be immediately closed. Perfect for testing.
	wsNop := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {}))
	defer wsNop.Close()

	// Get proxy to use for the test
	p := newWebSocketTestProxy(wsNop.URL)

	// Create client request
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	r.Header = http.Header{
		"Connection":            {"Upgrade"},
		"Upgrade":               {"websocket"},
		"Origin":                {wsNop.URL},
		"Sec-WebSocket-Key":     {"x3JJHMbDL1EzLkh9GBhXDw=="},
		"Sec-WebSocket-Version": {"13"},
	}

	// Capture the request
	w := &recorderHijacker{httptest.NewRecorder(), new(fakeConn)}

	// Booya! Do the test.
	p.ServeHTTP(w, r)

	// Make sure the backend accepted the WS connection.
	// Mostly interested in the Upgrade and Connection response headers
	// and the 101 status code.
	expected := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n\r\n")
	actual := w.fakeConn.writeBuf.Bytes()
	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected backend to accept response:\n'%s'\nActually got:\n'%s'", expected, actual)
	}
}

func TestWebSocketReverseProxyFromWSClient(t *testing.T) {
	// Echo server allows us to test that socket bytes are properly
	// being proxied.
	wsEcho := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		io.Copy(ws, ws)
	}))
	defer wsEcho.Close()

	// Get proxy to use for the test
	p := newWebSocketTestProxy(wsEcho.URL)

	// This is a full end-end test, so the proxy handler
	// has to be part of a server listening on a port. Our
	// WS client will connect to this test server, not
	// the echo client directly.
	echoProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	}))
	defer echoProxy.Close()

	// Set up WebSocket client
	url := strings.Replace(echoProxy.URL, "http://", "ws://", 1)
	ws, err := websocket.Dial(url, "", echoProxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	// Send test message
	trialMsg := "Is it working?"
	websocket.Message.Send(ws, trialMsg)

	// It should be echoed back to us
	var actualMsg string
	websocket.Message.Receive(ws, &actualMsg)
	if actualMsg != trialMsg {
		t.Errorf("Expected '%s' but got '%s' instead", trialMsg, actualMsg)
	}
}

func TestUnixSocketProxy(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}

	trialMsg := "Is it working?"

	var proxySuccess bool

	// This is our fake "application" we want to proxy to
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Request was proxied when this is called
		proxySuccess = true

		fmt.Fprint(w, trialMsg)
	}))

	// Get absolute path for unix: socket
	socketPath, err := filepath.Abs("./test_socket")
	if err != nil {
		t.Fatalf("Unable to get absolute path: %v", err)
	}

	// Change httptest.Server listener to listen to unix: socket
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Unable to listen: %v", err)
	}
	ts.Listener = ln

	ts.Start()
	defer ts.Close()

	url := strings.Replace(ts.URL, "http://", "unix:", 1)
	p := newWebSocketTestProxy(url)

	echoProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	}))
	defer echoProxy.Close()

	res, err := http.Get(echoProxy.URL)
	if err != nil {
		t.Fatalf("Unable to GET: %v", err)
	}

	greeting, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatalf("Unable to GET: %v", err)
	}

	actualMsg := fmt.Sprintf("%s", greeting)

	if !proxySuccess {
		t.Errorf("Expected request to be proxied, but it wasn't")
	}

	if actualMsg != trialMsg {
		t.Errorf("Expected '%s' but got '%s' instead", trialMsg, actualMsg)
	}
}

func newFakeUpstream(name string, insecure bool) *fakeUpstream {
	uri, _ := url.Parse(name)
	u := &fakeUpstream{
		name: name,
		host: &UpstreamHost{
			Name:         name,
			ReverseProxy: NewSingleHostReverseProxy(uri, ""),
		},
	}
	if insecure {
		u.host.ReverseProxy.Transport = InsecureTransport
	}
	return u
}

type fakeUpstream struct {
	name string
	host *UpstreamHost
}

func (u *fakeUpstream) From() string {
	return "/"
}

func (u *fakeUpstream) Select() *UpstreamHost {
	return u.host
}

func (u *fakeUpstream) IsAllowedPath(requestPath string) bool {
	return true
}

// newWebSocketTestProxy returns a test proxy that will
// redirect to the specified backendAddr. The function
// also sets up the rules/environment for testing WebSocket
// proxy.
func newWebSocketTestProxy(backendAddr string) *Proxy {
	return &Proxy{
		Upstreams: []Upstream{&fakeWsUpstream{name: backendAddr}},
	}
}

type fakeWsUpstream struct {
	name string
}

func (u *fakeWsUpstream) From() string {
	return "/"
}

func (u *fakeWsUpstream) Select() *UpstreamHost {
	uri, _ := url.Parse(u.name)
	return &UpstreamHost{
		Name:         u.name,
		ReverseProxy: NewSingleHostReverseProxy(uri, ""),
		ExtraHeaders: http.Header{
			"Connection": {"{>Connection}"},
			"Upgrade":    {"{>Upgrade}"}},
	}
}

func (u *fakeWsUpstream) IsAllowedPath(requestPath string) bool {
	return true
}

// recorderHijacker is a ResponseRecorder that can
// be hijacked.
type recorderHijacker struct {
	*httptest.ResponseRecorder
	fakeConn *fakeConn
}

func (rh *recorderHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return rh.fakeConn, nil, nil
}

type fakeConn struct {
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
}

func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) Read(b []byte) (int, error)         { return c.readBuf.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)        { return c.writeBuf.Write(b) }
