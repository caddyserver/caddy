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
	"sync/atomic"
	"testing"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"

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
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
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

	// Make sure {upstream} placeholder is set
	rr := httpserver.NewResponseRecorder(httptest.NewRecorder())
	rr.Replacer = httpserver.NewReplacer(r, rr, "-")

	p.ServeHTTP(rr, r)

	if got, want := rr.Replacer.Replace("{upstream}"), backend.URL; got != want {
		t.Errorf("Expected custom placeholder {upstream} to be set (%s), but it wasn't; got: %s", want, got)
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
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
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
	var connCount int32
	wsNop := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) { atomic.AddInt32(&connCount, 1) }))
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
	if atomic.LoadInt32(&connCount) != 1 {
		t.Errorf("Expected 1 websocket connection, got %d", connCount)
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

func GetHTTPProxy(messageFormat string, prefix string) (*Proxy, *httptest.Server) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, messageFormat, r.URL.String())
	}))

	return newPrefixedWebSocketTestProxy(ts.URL, prefix), ts
}

func GetSocketProxy(messageFormat string, prefix string) (*Proxy, *httptest.Server, error) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, messageFormat, r.URL.String())
	}))

	socketPath, err := filepath.Abs("./test_socket")
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to get absolute path: %v", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to listen: %v", err)
	}
	ts.Listener = ln

	ts.Start()

	tsURL := strings.Replace(ts.URL, "http://", "unix:", 1)

	return newPrefixedWebSocketTestProxy(tsURL, prefix), ts, nil
}

func GetTestServerMessage(p *Proxy, ts *httptest.Server, path string) (string, error) {
	echoProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	}))

	// *httptest.Server is passed so it can be `defer`red properly
	defer ts.Close()
	defer echoProxy.Close()

	res, err := http.Get(echoProxy.URL + path)
	if err != nil {
		return "", fmt.Errorf("Unable to GET: %v", err)
	}

	greeting, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return "", fmt.Errorf("Unable to read body: %v", err)
	}

	return fmt.Sprintf("%s", greeting), nil
}

func TestUnixSocketProxyPaths(t *testing.T) {
	greeting := "Hello route %s"

	tests := []struct {
		url      string
		prefix   string
		expected string
	}{
		{"", "", fmt.Sprintf(greeting, "/")},
		{"/hello", "", fmt.Sprintf(greeting, "/hello")},
		{"/foo/bar", "", fmt.Sprintf(greeting, "/foo/bar")},
		{"/foo?bar", "", fmt.Sprintf(greeting, "/foo?bar")},
		{"/greet?name=john", "", fmt.Sprintf(greeting, "/greet?name=john")},
		{"/world?wonderful&colorful", "", fmt.Sprintf(greeting, "/world?wonderful&colorful")},
		{"/proxy/hello", "/proxy", fmt.Sprintf(greeting, "/hello")},
		{"/proxy/foo/bar", "/proxy", fmt.Sprintf(greeting, "/foo/bar")},
		{"/proxy/?foo=bar", "/proxy", fmt.Sprintf(greeting, "/?foo=bar")},
		{"/queues/%2F/fetchtasks", "", fmt.Sprintf(greeting, "/queues/%2F/fetchtasks")},
		{"/queues/%2F/fetchtasks?foo=bar", "", fmt.Sprintf(greeting, "/queues/%2F/fetchtasks?foo=bar")},
	}

	for _, test := range tests {
		p, ts := GetHTTPProxy(greeting, test.prefix)

		actualMsg, err := GetTestServerMessage(p, ts, test.url)

		if err != nil {
			t.Fatalf("Getting server message failed - %v", err)
		}

		if actualMsg != test.expected {
			t.Errorf("Expected '%s' but got '%s' instead", test.expected, actualMsg)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}

	for _, test := range tests {
		p, ts, err := GetSocketProxy(greeting, test.prefix)

		if err != nil {
			t.Fatalf("Getting socket proxy failed - %v", err)
		}

		actualMsg, err := GetTestServerMessage(p, ts, test.url)

		if err != nil {
			t.Fatalf("Getting server message failed - %v", err)
		}

		if actualMsg != test.expected {
			t.Errorf("Expected '%s' but got '%s' instead", test.expected, actualMsg)
		}
	}
}

func TestUpstreamHeadersUpdate(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	var actualHeaders http.Header
	var actualHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, client"))
		actualHeaders = r.Header
		actualHost = r.Host
	}))
	defer backend.Close()

	upstream := newFakeUpstream(backend.URL, false)
	upstream.host.UpstreamHeaders = http.Header{
		"Connection": {"{>Connection}"},
		"Upgrade":    {"{>Upgrade}"},
		"+Merge-Me":  {"Merge-Value"},
		"+Add-Me":    {"Add-Value"},
		"-Remove-Me": {""},
		"Replace-Me": {"{hostname}"},
		"Host":       {"{>Host}"},
	}
	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{upstream},
	}

	// create request and response recorder
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	const expectHost = "example.com"
	//add initial headers
	r.Header.Add("Merge-Me", "Initial")
	r.Header.Add("Remove-Me", "Remove-Value")
	r.Header.Add("Replace-Me", "Replace-Value")
	r.Header.Add("Host", expectHost)

	p.ServeHTTP(w, r)

	replacer := httpserver.NewReplacer(r, nil, "")

	headerKey := "Merge-Me"
	values, ok := actualHeaders[headerKey]
	if !ok {
		t.Errorf("Request sent to upstream backend does not contain expected %v header. Expected header to be added", headerKey)
	} else if len(values) < 2 && (values[0] != "Initial" || values[1] != replacer.Replace("{hostname}")) {
		t.Errorf("Values for proxy header `+Merge-Me` should be merged. Got %v", values)
	}

	headerKey = "Add-Me"
	if _, ok := actualHeaders[headerKey]; !ok {
		t.Errorf("Request sent to upstream backend does not contain expected %v header", headerKey)
	}

	headerKey = "Remove-Me"
	if _, ok := actualHeaders[headerKey]; ok {
		t.Errorf("Request sent to upstream backend should not contain %v header", headerKey)
	}

	headerKey = "Replace-Me"
	headerValue := replacer.Replace("{hostname}")
	value, ok := actualHeaders[headerKey]
	if !ok {
		t.Errorf("Request sent to upstream backend should not remove %v header", headerKey)
	} else if len(value) > 0 && headerValue != value[0] {
		t.Errorf("Request sent to upstream backend should replace value of %v header with %v. Instead value was %v", headerKey, headerValue, value)
	}

	if actualHost != expectHost {
		t.Errorf("Request sent to upstream backend should have value of Host with %s, but got %s", expectHost, actualHost)
	}

}

func TestDownstreamHeadersUpdate(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Merge-Me", "Initial")
		w.Header().Add("Remove-Me", "Remove-Value")
		w.Header().Add("Replace-Me", "Replace-Value")
		w.Write([]byte("Hello, client"))
	}))
	defer backend.Close()

	upstream := newFakeUpstream(backend.URL, false)
	upstream.host.DownstreamHeaders = http.Header{
		"+Merge-Me":  {"Merge-Value"},
		"+Add-Me":    {"Add-Value"},
		"-Remove-Me": {""},
		"Replace-Me": {"{hostname}"},
	}
	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{upstream},
	}

	// create request and response recorder
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	replacer := httpserver.NewReplacer(r, nil, "")
	actualHeaders := w.Header()

	headerKey := "Merge-Me"
	values, ok := actualHeaders[headerKey]
	if !ok {
		t.Errorf("Downstream response does not contain expected %v header. Expected header should be added", headerKey)
	} else if len(values) < 2 && (values[0] != "Initial" || values[1] != replacer.Replace("{hostname}")) {
		t.Errorf("Values for header `+Merge-Me` should be merged. Got %v", values)
	}

	headerKey = "Add-Me"
	if _, ok := actualHeaders[headerKey]; !ok {
		t.Errorf("Downstream response does not contain expected %v header", headerKey)
	}

	headerKey = "Remove-Me"
	if _, ok := actualHeaders[headerKey]; ok {
		t.Errorf("Downstream response should not contain %v header received from upstream", headerKey)
	}

	headerKey = "Replace-Me"
	headerValue := replacer.Replace("{hostname}")
	value, ok := actualHeaders[headerKey]
	if !ok {
		t.Errorf("Downstream response should contain %v header and not remove it", headerKey)
	} else if len(value) > 0 && headerValue != value[0] {
		t.Errorf("Downstream response should have header %v with value %v. Instead value was %v", headerKey, headerValue, value)
	}

}

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
	p := &Proxy{
		Next: httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{
			// The order is important; the short path should go first to ensure
			// we choose the most specific route, not the first one.
			&fakeUpstream{
				name: upstreamServer1.URL,
				from: "/",
			},
			&fakeUpstream{
				name: upstreamServer2.URL,
				from: "/api",
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

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if !bytes.Equal(body, tt.body) {
			t.Errorf("Expected '%s' but got '%s' instead", tt.body, body)
		}
	}
}

func TestHostSimpleProxyNoHeaderForward(t *testing.T) {
	var requestHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHost = r.Host
		w.Write([]byte("Hello, client"))
	}))
	defer backend.Close()

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{newFakeUpstream(backend.URL, false)},
	}

	r, err := http.NewRequest("GET", "/", nil)
	r.Host = "test.com"

	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	if !strings.Contains(backend.URL, "//") {
		t.Fatalf("The URL of the backend server doesn't contains //: %s", backend.URL)
	}

	expectedHost := strings.Split(backend.URL, "//")
	if expectedHost[1] != requestHost {
		t.Fatalf("Expected %s as a Host header got %s\n", expectedHost[1], requestHost)
	}
}

func TestHostHeaderReplacedUsingForward(t *testing.T) {
	var requestHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHost = r.Host
		w.Write([]byte("Hello, client"))
	}))
	defer backend.Close()

	upstream := newFakeUpstream(backend.URL, false)
	proxyHostHeader := "test2.com"
	upstream.host.UpstreamHeaders = http.Header{"Host": []string{proxyHostHeader}}
	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{upstream},
	}

	r, err := http.NewRequest("GET", "/", nil)
	r.Host = "test.com"

	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	if proxyHostHeader != requestHost {
		t.Fatalf("Expected %s as a Host header got %s\n", proxyHostHeader, requestHost)
	}
}

func TestBasicAuth(t *testing.T) {
	basicAuthTestcase(t, nil, nil)
	basicAuthTestcase(t, nil, url.UserPassword("username", "password"))
	basicAuthTestcase(t, url.UserPassword("usename", "password"), nil)
	basicAuthTestcase(t, url.UserPassword("unused", "unused"),
		url.UserPassword("username", "password"))
}

func basicAuthTestcase(t *testing.T, upstreamUser, clientUser *url.Userinfo) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()

		if ok {
			w.Write([]byte(u))
		}
		if ok && p != "" {
			w.Write([]byte(":"))
			w.Write([]byte(p))
		}
	}))
	defer backend.Close()

	backURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}
	backURL.User = upstreamUser

	p := &Proxy{
		Next:      httpserver.EmptyNext,
		Upstreams: []Upstream{newFakeUpstream(backURL.String(), false)},
	}
	r, err := http.NewRequest("GET", "/foo", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	if clientUser != nil {
		u := clientUser.Username()
		p, _ := clientUser.Password()
		r.SetBasicAuth(u, p)
	}
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("Invalid response code: %d", w.Code)
	}
	body, _ := ioutil.ReadAll(w.Body)

	if clientUser != nil {
		if string(body) != clientUser.String() {
			t.Fatalf("Invalid auth info: %s", string(body))
		}
	} else {
		if upstreamUser != nil {
			if string(body) != upstreamUser.String() {
				t.Fatalf("Invalid auth info: %s", string(body))
			}
		} else {
			if string(body) != "" {
				t.Fatalf("Invalid auth info: %s", string(body))
			}
		}
	}
}

func newFakeUpstream(name string, insecure bool) *fakeUpstream {
	uri, _ := url.Parse(name)
	u := &fakeUpstream{
		name: name,
		from: "/",
		host: &UpstreamHost{
			Name:         name,
			ReverseProxy: NewSingleHostReverseProxy(uri, "", http.DefaultMaxIdleConnsPerHost),
		},
	}
	if insecure {
		u.host.ReverseProxy.UseInsecureTransport()
	}
	return u
}

type fakeUpstream struct {
	name    string
	host    *UpstreamHost
	from    string
	without string
}

func (u *fakeUpstream) From() string {
	return u.from
}

func (u *fakeUpstream) Select(r *http.Request) *UpstreamHost {
	if u.host == nil {
		uri, err := url.Parse(u.name)
		if err != nil {
			log.Fatalf("Unable to url.Parse %s: %v", u.name, err)
		}
		u.host = &UpstreamHost{
			Name:         u.name,
			ReverseProxy: NewSingleHostReverseProxy(uri, u.without, http.DefaultMaxIdleConnsPerHost),
		}
	}
	return u.host
}

func (u *fakeUpstream) AllowedPath(requestPath string) bool {
	return true
}

// newWebSocketTestProxy returns a test proxy that will
// redirect to the specified backendAddr. The function
// also sets up the rules/environment for testing WebSocket
// proxy.
func newWebSocketTestProxy(backendAddr string) *Proxy {
	return &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{&fakeWsUpstream{name: backendAddr, without: ""}},
	}
}

func newPrefixedWebSocketTestProxy(backendAddr string, prefix string) *Proxy {
	return &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{&fakeWsUpstream{name: backendAddr, without: prefix}},
	}
}

type fakeWsUpstream struct {
	name    string
	without string
}

func (u *fakeWsUpstream) From() string {
	return "/"
}

func (u *fakeWsUpstream) Select(r *http.Request) *UpstreamHost {
	uri, _ := url.Parse(u.name)
	return &UpstreamHost{
		Name:         u.name,
		ReverseProxy: NewSingleHostReverseProxy(uri, u.without, http.DefaultMaxIdleConnsPerHost),
		UpstreamHeaders: http.Header{
			"Connection": {"{>Connection}"},
			"Upgrade":    {"{>Upgrade}"}},
	}
}

func (u *fakeWsUpstream) AllowedPath(requestPath string) bool {
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

func BenchmarkProxy(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, client"))
	}))
	defer backend.Close()

	upstream := newFakeUpstream(backend.URL, false)
	upstream.host.UpstreamHeaders = http.Header{
		"Hostname":          {"{hostname}"},
		"Host":              {"{host}"},
		"X-Real-IP":         {"{remote}"},
		"X-Forwarded-Proto": {"{scheme}"},
	}
	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{upstream},
	}

	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// create request and response recorder
		r, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			b.Fatalf("Failed to create request: %v", err)
		}
		b.StartTimer()
		p.ServeHTTP(w, r)
	}
}
