package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

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

// newWebSocketTestProxy returns a test proxy that will
// redirect to the specified backendAddr. The function
// also sets up the rules/environment for testing WebSocket
// proxy.
func newWebSocketTestProxy(backendAddr string) *Proxy {
	return &Proxy{
		Upstreams: []Upstream{
			&fakeUpstream{
				name: backendAddr,
				from: "/",
				extraHeaders: http.Header{
					"Connection": {"{>Connection}"},
					"Upgrade":    {"{>Upgrade}"},
				},
			},
		},
	}
}

type fakeUpstream struct {
	name         string
	from         string
	without      string
	extraHeaders http.Header
}

func (u *fakeUpstream) From() string {
	return u.from
}

func (u *fakeUpstream) Select() *UpstreamHost {
	uri, _ := url.Parse(u.name)
	return &UpstreamHost{
		Name:         u.name,
		ReverseProxy: NewSingleHostReverseProxy(uri, u.without),
		ExtraHeaders: u.extraHeaders,
	}
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

var (
	upstreamResp1 = []byte("Hello, /")
	upstreamResp2 = []byte("Hello, /api/")
)

func newMultiHostTestProxy() *Proxy {
	// No-op backends.
	upstreamServer1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", upstreamResp1)
	}))
	upstreamServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", upstreamResp2)
	}))

	// Test proxy.
	p := &Proxy{
		Upstreams: []Upstream{
			&fakeUpstream{
				name: upstreamServer1.URL,
				from: "/",
				extraHeaders: http.Header{
					"Host": {"example.com"},
				},
			},
			&fakeUpstream{
				name: upstreamServer2.URL,
				from: "/api",
				extraHeaders: http.Header{
					"Host": {"example.net"},
				},
			},
		},
	}
	return p
}

func TestMultiReverseProxyFromClient(t *testing.T) {
	p := newMultiHostTestProxy()

	// This is a full end-end test, so the proxy handler.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	}))
	defer proxy.Close()

	// Table tests.
	var multiProxy = []struct {
		url  string
		body []byte
	}{
		{
			"/",
			upstreamResp1,
		},
		{
			"/api/",
			upstreamResp2,
		},
		{
			"/messages/",
			upstreamResp1,
		},
		{
			"/api/messages/?text=cat",
			upstreamResp2,
		},
	}

	for _, tt := range multiProxy {
		// Create client request
		reqURL := singleJoiningSlash(proxy.URL, tt.url)
		req, err := http.NewRequest("GET", reqURL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		defer resp.Body.Close()
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read responce: %v", err)
		}

		if !bytes.Equal(body, tt.body) {
			t.Errorf("Expected '%s' but got '%s' instead", tt.body, body)
		}
	}
}

func T1estMultiReverseProxyServeHostHeader(t *testing.T) {
	p := newMultiHostTestProxy()

	// Table tests.
	var multiHostHeader = []struct {
		url          string
		extraHeaders http.Header
	}{
		{
			"/",
			http.Header{
				"Host": {"example.com"},
			},
		},
		{
			"/api/",
			http.Header{
				"Host": {"example.net"},
			},
		},
		{
			"/messages/",
			http.Header{
				"Host": {"example.com"},
			},
		},
		{
			"/api/messages/?text=cat",
			http.Header{
				"Host": {"example.net"},
			},
		},
	}

	for _, tt := range multiHostHeader {
		// Create client request
		r, err := http.NewRequest("GET", tt.url, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Capture the request
		w := httptest.NewRecorder()

		// Booya! Do the test.
		p.ServeHTTP(w, r)

		host := r.Header.Get("Host")
		if host != tt.extraHeaders.Get("Host") {
			t.Errorf("Expected Host Header '%s' but got '%s' instead", tt.extraHeaders.Get("Host"), host)
		}
	}
}
