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

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/caddyserver/caddy/caddyfile"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"

	"golang.org/x/net/websocket"
)

// This is a simple wrapper around httptest.NewTLSServer()
// which forcefully enables (among others) HTTP/2 support.
// The httptest package only supports HTTP/1.1 by default.
func newTLSServer(handler http.Handler) *httptest.Server {
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = new(tls.Config)
	ts.TLS.NextProtos = []string{"h2"}
	ts.StartTLS()
	return ts
}

func TestReverseProxy(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	testHeaderValue := []string{"header-value"}
	testHeaders := http.Header{
		"X-Header-1": testHeaderValue,
		"X-Header-2": testHeaderValue,
		"X-Header-3": testHeaderValue,
	}
	testTrailerValue := []string{"trailer-value"}
	testTrailers := http.Header{
		"X-Trailer-1": testTrailerValue,
		"X-Trailer-2": testTrailerValue,
		"X-Trailer-3": testTrailerValue,
	}
	verifyHeaderValues := func(actual http.Header, expected http.Header) bool {
		if actual == nil {
			t.Error("Expected headers")
			return true
		}

		for k := range expected {
			if expected.Get(k) != actual.Get(k) {
				t.Errorf("Expected header '%s' to be proxied properly", k)
				return true
			}
		}

		return false
	}
	verifyHeadersTrailers := func(headers http.Header, trailers http.Header) {
		if verifyHeaderValues(headers, testHeaders) || verifyHeaderValues(trailers, testTrailers) {
			t.FailNow()
		}
	}

	requestReceived := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// read the body (even if it's empty) to make Go parse trailers
		if _, err := io.Copy(ioutil.Discard, r.Body); err != nil {
			log.Println("[ERROR] failed to copy bytes: ", err)
		}

		verifyHeadersTrailers(r.Header, r.Trailer)
		requestReceived = true

		// Set headers.
		copyHeader(w.Header(), testHeaders)

		// Only announce one of the trailers to test whether
		// unannounced trailers are proxied correctly.
		for k := range testTrailers {
			w.Header().Set("Trailer", k)
			break
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Hello, client")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}

		// Set trailers.
		shallowCopyTrailers(w.Header(), testTrailers, true)
	}))
	defer backend.Close()

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{newFakeUpstream(backend.URL, false, 30*time.Second, 300*time.Millisecond)},
	}

	// Create the fake request body.
	// This will copy "trailersToSet" to r.Trailer right before it is closed and
	// thus test for us whether unannounced client trailers are proxied correctly.
	body := &trailerTestStringReader{
		Reader:        *strings.NewReader("test"),
		trailersToSet: testTrailers,
	}

	// Create the fake request with the above body.
	r := httptest.NewRequest("GET", "/", body)
	r.Trailer = make(http.Header)
	body.request = r

	copyHeader(r.Header, testHeaders)

	// Only announce one of the trailers to test whether
	// unannounced trailers are proxied correctly.
	for k, v := range testTrailers {
		r.Trailer[k] = v
		break
	}

	w := httptest.NewRecorder()
	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}
	res := w.Result()

	if !requestReceived {
		t.Error("Expected backend to receive request, but it didn't")
	}

	verifyHeadersTrailers(res.Header, res.Trailer)

	// Make sure {upstream} placeholder is set
	r.Body = ioutil.NopCloser(strings.NewReader("test"))
	rr := httpserver.NewResponseRecorder(testResponseRecorder{
		ResponseWriterWrapper: &httpserver.ResponseWriterWrapper{ResponseWriter: httptest.NewRecorder()},
	})
	rr.Replacer = httpserver.NewReplacer(r, rr, "-")

	if _, err := p.ServeHTTP(rr, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

	if got, want := rr.Replacer.Replace("{upstream}"), backend.URL; got != want {
		t.Errorf("Expected custom placeholder {upstream} to be set (%s), but it wasn't; got: %s", want, got)
	}
}

// trailerTestStringReader is used to test unannounced trailers coming
// from a client which should properly be proxied to the upstream.
type trailerTestStringReader struct {
	strings.Reader
	request       *http.Request
	trailersToSet http.Header
}

var _ io.ReadCloser = &trailerTestStringReader{}

func (r *trailerTestStringReader) Close() error {
	copyHeader(r.request.Trailer, r.trailersToSet)
	return nil
}

func TestReverseProxyInsecureSkipVerify(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	var requestReceived bool
	var requestWasHTTP2 bool
	backend := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		requestWasHTTP2 = r.ProtoAtLeast(2, 0)
		if _, err := w.Write([]byte("Hello, client")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}
	}))
	defer backend.Close()

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{newFakeUpstream(backend.URL, true, 30*time.Second, 300*time.Millisecond)},
	}

	// create request and response recorder
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

	if !requestReceived {
		t.Error("Even with insecure HTTPS, expected backend to receive request, but it didn't")
	}
	if !requestWasHTTP2 {
		t.Error("Even with insecure HTTPS, expected proxy to use HTTP/2")
	}
}

// This test will fail when using the race detector without atomic reads &
// writes of UpstreamHost.Conns and UpstreamHost.Unhealthy.
func TestReverseProxyMaxConnLimit(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	const MaxTestConns = 2
	connReceived := make(chan bool, MaxTestConns)
	connContinue := make(chan bool)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connReceived <- true
		<-connContinue
	}))
	defer backend.Close()

	su, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(`
		proxy / `+backend.URL+` {
			max_conns `+fmt.Sprint(MaxTestConns)+`
		}
	`)), "")
	if err != nil {
		t.Fatal(err)
	}

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: su,
	}

	var jobs sync.WaitGroup

	for i := 0; i < MaxTestConns; i++ {
		jobs.Add(1)
		go func(i int) {
			defer jobs.Done()
			w := httptest.NewRecorder()
			code, err := p.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
			if err != nil {
				t.Errorf("Request %d failed: %v", i, err)
			} else if code != 0 {
				t.Errorf("Bad return code for request %d: %d", i, code)
			} else if w.Code != 200 {
				t.Errorf("Bad status code for request %d: %d", i, w.Code)
			}
		}(i)
	}
	// Wait for all the requests to hit the backend.
	for i := 0; i < MaxTestConns; i++ {
		<-connReceived
	}

	// Now we should have MaxTestConns requests connected and sitting on the backend
	// server.  Verify that the next request is rejected.
	w := httptest.NewRecorder()
	code, err := p.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if code != http.StatusBadGateway {
		t.Errorf("Expected request to be rejected, but got: %d [%v]\nStatus code: %d",
			code, err, w.Code)
	}

	// Now let all the requests complete and verify the status codes for those:
	close(connContinue)

	// Wait for the initial requests to finish and check their results.
	jobs.Wait()
}

func TestReverseProxyTimeout(t *testing.T) {
	timeout := 2 * time.Second
	fallbackDelay := 300 * time.Millisecond
	errorMargin := 100 * time.Millisecond
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{newFakeUpstream("https://8.8.8.8", true, timeout, fallbackDelay)},
	}

	// create request and response recorder
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}
	took := time.Since(start)

	if took > timeout+errorMargin {
		t.Errorf("Expected timeout ~ %v but got %v", timeout, took)
	}
}

func TestWebSocketReverseProxyNonHijackerPanic(t *testing.T) {
	// Capture the expected panic
	defer func() {
		r := recover()
		if _, ok := r.(httpserver.NonHijackerError); !ok {
			t.Error("not get the expected panic")
		}
	}()

	var connCount int32
	wsNop := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) { atomic.AddInt32(&connCount, 1) }))
	defer wsNop.Close()

	// Get proxy to use for the test
	p := newWebSocketTestProxy(wsNop.URL, false, 30*time.Second)

	// Create client request
	r := httptest.NewRequest("GET", "/", nil)

	r.Header = http.Header{
		"Connection":            {"Upgrade"},
		"Upgrade":               {"websocket"},
		"Origin":                {wsNop.URL},
		"Sec-WebSocket-Key":     {"x3JJHMbDL1EzLkh9GBhXDw=="},
		"Sec-WebSocket-Version": {"13"},
	}

	nonHijacker := httptest.NewRecorder()
	if _, err := p.ServeHTTP(nonHijacker, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}
}

func TestWebSocketReverseProxyBackendShutDown(t *testing.T) {
	shutdown := make(chan struct{})
	backend := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		shutdown <- struct{}{}
	}))
	defer backend.Close()

	go func() {
		<-shutdown
		backend.Close()
	}()

	// Get proxy to use for the test
	p := newWebSocketTestProxy(backend.URL, false, 30*time.Second)
	backendProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := p.ServeHTTP(w, r); err != nil {
			log.Println("[ERROR] failed to serve HTTP: ", err)
		}
	}))
	defer backendProxy.Close()

	// Set up WebSocket client
	url := strings.Replace(backendProxy.URL, "http://", "ws://", 1)
	ws, err := websocket.Dial(url, "", backendProxy.URL)

	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	var actualMsg string
	if rcvErr := websocket.Message.Receive(ws, &actualMsg); rcvErr == nil {
		t.Errorf("we don't get backend shutdown notification")
	}
}

func TestWebSocketReverseProxyServeHTTPHandler(t *testing.T) {
	// No-op websocket backend simply allows the WS connection to be
	// accepted then it will be immediately closed. Perfect for testing.
	accepted := make(chan struct{})
	wsNop := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) { close(accepted) }))
	defer wsNop.Close()

	// Get proxy to use for the test
	p := newWebSocketTestProxy(wsNop.URL, false, 30*time.Second)

	// Create client request
	r := httptest.NewRequest("GET", "/", nil)

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
	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

	// Make sure the backend accepted the WS connection.
	// Mostly interested in the Upgrade and Connection response headers
	// and the 101 status code.
	expected := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n\r\n")
	actual := w.fakeConn.writeBuf.Bytes()
	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected backend to accept response:\n'%s'\nActually got:\n'%s'", expected, actual)
	}

	// wait a minute for backend handling, see issue 1654.
	time.Sleep(10 * time.Millisecond)

	select {
	case <-accepted:
	default:
		t.Error("Expect a accepted websocket connection, but not")
	}
}

func TestWebSocketReverseProxyFromWSClient(t *testing.T) {
	// Echo server allows us to test that socket bytes are properly
	// being proxied.
	wsEcho := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		if _, err := io.Copy(ws, ws); err != nil {
			log.Println("[ERROR] failed to copy: ", err)
		}
	}))
	defer wsEcho.Close()

	// Get proxy to use for the test
	p := newWebSocketTestProxy(wsEcho.URL, false, 30*time.Second)

	// This is a full end-end test, so the proxy handler
	// has to be part of a server listening on a port. Our
	// WS client will connect to this test server, not
	// the echo client directly.
	echoProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := p.ServeHTTP(w, r); err != nil {
			log.Println("[ERROR] failed to serve HTTP: ", err)
		}
	}))
	defer echoProxy.Close()

	// Set up WebSocket client
	u := strings.Replace(echoProxy.URL, "http://", "ws://", 1)
	ws, err := websocket.Dial(u, "", echoProxy.URL)

	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	// Send test message
	trialMsg := "Is it working?"

	if sendErr := websocket.Message.Send(ws, trialMsg); sendErr != nil {
		t.Fatal(sendErr)
	}

	// It should be echoed back to us
	var actualMsg string

	if rcvErr := websocket.Message.Receive(ws, &actualMsg); rcvErr != nil {
		t.Fatal(rcvErr)
	}

	if actualMsg != trialMsg {
		t.Errorf("Expected '%s' but got '%s' instead", trialMsg, actualMsg)
	}
}

func TestWebSocketReverseProxyFromWSSClient(t *testing.T) {
	wsEcho := newTLSServer(websocket.Handler(func(ws *websocket.Conn) {
		if _, err := io.Copy(ws, ws); err != nil {
			log.Println("[ERROR] failed to copy: ", err)
		}
	}))
	defer wsEcho.Close()

	p := newWebSocketTestProxy(wsEcho.URL, true, 30*time.Second)

	echoProxy := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := p.ServeHTTP(w, r); err != nil {
			log.Println("[ERROR] failed to serve HTTP: ", err)
		}
	}))
	defer echoProxy.Close()

	// Set up WebSocket client
	u := strings.Replace(echoProxy.URL, "https://", "wss://", 1)
	wsCfg, err := websocket.NewConfig(u, echoProxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsCfg.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	ws, err := websocket.DialConfig(wsCfg)

	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	// Send test message
	trialMsg := "Is it working?"

	if sendErr := websocket.Message.Send(ws, trialMsg); sendErr != nil {
		t.Fatal(sendErr)
	}

	// It should be echoed back to us
	var actualMsg string

	if rcvErr := websocket.Message.Receive(ws, &actualMsg); rcvErr != nil {
		t.Fatal(rcvErr)
	}

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
	dir, err := ioutil.TempDir("", "caddy_proxytest")
	if err != nil {
		t.Fatalf("Failed to make temp dir to contain unix socket. %v", err)
	}
	defer os.RemoveAll(dir)
	socketPath := filepath.Join(dir, "test_socket")

	// Change httptest.Server listener to listen to unix: socket
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Unable to listen: %v", err)
	}
	ts.Listener = ln

	ts.Start()
	defer ts.Close()

	url := strings.Replace(ts.URL, "http://", "unix:", 1)
	p := newWebSocketTestProxy(url, false, 30*time.Second)

	echoProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := p.ServeHTTP(w, r); err != nil {
			log.Println("[ERROR] failed to serve HTTP: ", err)
		}
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

func GetSocketProxy(messageFormat string, prefix string) (*Proxy, *httptest.Server, string, error) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, messageFormat, r.URL.String())
	}))

	dir, err := ioutil.TempDir("", "caddy_proxytest")
	if err != nil {
		return nil, nil, dir, fmt.Errorf("failed to make temp dir to contain unix socket. %v", err)
	}
	socketPath := filepath.Join(dir, "test_socket")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		os.RemoveAll(dir)
		return nil, nil, dir, fmt.Errorf("unable to listen: %v", err)
	}
	ts.Listener = ln

	ts.Start()

	tsURL := strings.Replace(ts.URL, "http://", "unix:", 1)

	return newPrefixedWebSocketTestProxy(tsURL, prefix), ts, dir, nil
}

func GetTestServerMessage(p *Proxy, ts *httptest.Server, path string) (string, error) {
	echoProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := p.ServeHTTP(w, r); err != nil {
			log.Println("[ERROR] failed to serve HTTP: ", err)
		}
	}))

	// *httptest.Server is passed so it can be `defer`red properly
	defer ts.Close()
	defer echoProxy.Close()

	res, err := http.Get(echoProxy.URL + path)
	if err != nil {
		return "", fmt.Errorf("unable to GET: %v", err)
	}

	greeting, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return "", fmt.Errorf("unable to read body: %v", err)
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
		p, ts, tmpdir, err := GetSocketProxy(greeting, test.prefix)
		if err != nil {
			t.Fatalf("Getting socket proxy failed - %v", err)
		}

		actualMsg, err := GetTestServerMessage(p, ts, test.url)

		if err != nil {
			os.RemoveAll(tmpdir)
			t.Fatalf("Getting server message failed - %v", err)
		}

		if actualMsg != test.expected {
			t.Errorf("Expected '%s' but got '%s' instead", test.expected, actualMsg)
		}

		os.RemoveAll(tmpdir)
	}
}

func TestUpstreamHeadersUpdate(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	var actualHeaders http.Header
	var actualHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Hello, client")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}
		actualHeaders = r.Header
		actualHost = r.Host
	}))
	defer backend.Close()

	upstream := newFakeUpstream(backend.URL, false, 30*time.Second, 300*time.Millisecond)
	upstream.host.UpstreamHeaders = http.Header{
		"Connection": {"{>Connection}"},
		"Upgrade":    {"{>Upgrade}"},
		"+Merge-Me":  {"Merge-Value"},
		"+Add-Me":    {"Add-Value"},
		"+Add-Empty": {"{}"},
		"-Remove-Me": {""},
		"Replace-Me": {"{hostname}"},
		"Clear-Me":   {""},
		"Host":       {"{>Host}"},
	}
	regex1, _ := regexp.Compile("was originally")
	regex2, _ := regexp.Compile("this")
	regex3, _ := regexp.Compile("bad")
	upstream.host.UpstreamHeaderReplacements = headerReplacements{
		"Regex-Me":        {headerReplacement{regex1, "am now"}, headerReplacement{regex2, "that"}},
		"Regexreplace-Me": {headerReplacement{regex3, "{hostname}"}},
	}

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{upstream},
	}

	// create request and response recorder
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	const expectHost = "example.com"
	//add initial headers
	r.Header.Add("Merge-Me", "Initial")
	r.Header.Add("Remove-Me", "Remove-Value")
	r.Header.Add("Replace-Me", "Replace-Value")
	r.Header.Add("Host", expectHost)
	r.Header.Add("Regex-Me", "I was originally this")
	r.Header.Add("Regexreplace-Me", "The host is bad")

	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

	replacer := httpserver.NewReplacer(r, nil, "")

	for headerKey, expect := range map[string][]string{
		"Merge-Me":        {"Initial", "Merge-Value"},
		"Add-Me":          {"Add-Value"},
		"Add-Empty":       nil,
		"Remove-Me":       nil,
		"Replace-Me":      {replacer.Replace("{hostname}")},
		"Clear-Me":        nil,
		"Regex-Me":        {"I am now that"},
		"Regexreplace-Me": {"The host is " + replacer.Replace("{hostname}")},
	} {
		if got := actualHeaders[headerKey]; !reflect.DeepEqual(got, expect) {
			t.Errorf("Upstream request does not contain expected %v header: expect %v, but got %v",
				headerKey, expect, got)
		}
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
		w.Header().Add("Content-Type", "text/html")
		w.Header().Add("Overwrite-Me", "Overwrite-Value")
		w.Header().Add("Regex-Me", "I was originally this")
		w.Header().Add("Regexreplace-Me", "The host is bad")
		if _, err := w.Write([]byte("Hello, client")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}
	}))
	defer backend.Close()

	upstream := newFakeUpstream(backend.URL, false, 30*time.Second, 300*time.Millisecond)
	upstream.host.DownstreamHeaders = http.Header{
		"+Merge-Me":  {"Merge-Value"},
		"+Add-Me":    {"Add-Value"},
		"-Remove-Me": {""},
		"Replace-Me": {"{hostname}"},
	}
	regex1, _ := regexp.Compile("was originally")
	regex2, _ := regexp.Compile("this")
	regex3, _ := regexp.Compile("bad")
	upstream.host.DownstreamHeaderReplacements = headerReplacements{
		"Regex-Me":        {headerReplacement{regex1, "am now"}, headerReplacement{regex2, "that"}},
		"Regexreplace-Me": {headerReplacement{regex3, "{hostname}"}},
	}
	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{upstream},
	}

	// create request and response recorder
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	// set a predefined skip header
	w.Header().Set("Content-Type", "text/css")
	// set a predefined overwritten header
	w.Header().Set("Overwrite-Me", "Initial")

	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

	replacer := httpserver.NewReplacer(r, nil, "")
	actualHeaders := w.Header()

	for headerKey, expect := range map[string][]string{
		"Merge-Me":        {"Initial", "Merge-Value"},
		"Add-Me":          {"Add-Value"},
		"Remove-Me":       nil,
		"Replace-Me":      {replacer.Replace("{hostname}")},
		"Content-Type":    {"text/css"},
		"Overwrite-Me":    {"Overwrite-Value"},
		"Regex-Me":        {"I am now that"},
		"Regexreplace-Me": {"The host is " + replacer.Replace("{hostname}")},
	} {
		if got := actualHeaders[headerKey]; !reflect.DeepEqual(got, expect) {
			t.Errorf("Downstream response does not contain expected %s header: expect %v, but got %v",
				headerKey, expect, got)
		}
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
		if _, err := p.ServeHTTP(w, r); err != nil {
			log.Println("[ERROR] failed to serve HTTP: ", err)
		}
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
		reqURL := proxy.URL + tt.url
		req, err := http.NewRequest("GET", reqURL, nil)

		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
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
		if _, err := w.Write([]byte("Hello, client")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}
	}))
	defer backend.Close()

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{newFakeUpstream(backend.URL, false, 30*time.Second, 300*time.Millisecond)},
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "test.com"

	w := httptest.NewRecorder()

	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

	if !strings.Contains(backend.URL, "//") {
		t.Fatalf("The URL of the backend server doesn't contains //: %s", backend.URL)
	}

	expectedHost := strings.Split(backend.URL, "//")
	if expectedHost[1] != requestHost {
		t.Fatalf("Expected %s as a Host header got %s\n", expectedHost[1], requestHost)
	}
}

func TestReverseProxyTransparentHeaders(t *testing.T) {
	testCases := []struct {
		name               string
		remoteAddr         string
		forwardedForHeader string
		expected           []string
	}{
		{"No header", "192.168.0.1:80", "", []string{"192.168.0.1"}},
		{"Existing", "192.168.0.1:80", "1.1.1.1, 2.2.2.2", []string{"1.1.1.1, 2.2.2.2, 192.168.0.1"}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testReverseProxyTransparentHeaders(t, tc.remoteAddr, tc.forwardedForHeader, tc.expected)
		})
	}
}

func testReverseProxyTransparentHeaders(t *testing.T, remoteAddr, forwardedForHeader string, expected []string) {
	// Arrange
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	var actualHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actualHeaders = r.Header
	}))
	defer backend.Close()

	config := "proxy / " + backend.URL + " {\n transparent \n}"

	// make proxy
	upstreams, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(config)), "")
	if err != nil {
		t.Errorf("Expected no error. Got: %s", err.Error())
	}

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: upstreams,
	}

	// create request and response recorder
	r := httptest.NewRequest("GET", backend.URL, nil)
	r.RemoteAddr = remoteAddr
	if forwardedForHeader != "" {
		r.Header.Set("X-Forwarded-For", forwardedForHeader)
	}

	w := httptest.NewRecorder()

	// Act
	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

	// Assert
	if got := actualHeaders["X-Forwarded-For"]; !reflect.DeepEqual(got, expected) {
		t.Errorf("Transparent proxy response does not contain expected %v header: expect %v, but got %v",
			"X-Forwarded-For", expected, got)
	}
}

func TestHostHeaderReplacedUsingForward(t *testing.T) {
	var requestHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHost = r.Host
		if _, err := w.Write([]byte("Hello, client")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}
	}))
	defer backend.Close()

	upstream := newFakeUpstream(backend.URL, false, 30*time.Second, 300*time.Millisecond)
	proxyHostHeader := "test2.com"
	upstream.host.UpstreamHeaders = http.Header{"Host": []string{proxyHostHeader}}
	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{upstream},
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "test.com"

	w := httptest.NewRecorder()

	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

	if proxyHostHeader != requestHost {
		t.Fatalf("Expected %s as a Host header got %s\n", proxyHostHeader, requestHost)
	}
}

func TestBasicAuth(t *testing.T) {
	testCases := []struct {
		name         string
		upstreamUser *url.Userinfo
		clientUser   *url.Userinfo
	}{
		{"Nil Both", nil, nil},
		{"Nil Upstream User", nil, url.UserPassword("username", "password")},
		{"Nil Client User", url.UserPassword("username", "password"), nil},
		{"Both Provided", url.UserPassword("unused", "unused"),
			url.UserPassword("username", "password")},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			basicAuthTestcase(t, tc.upstreamUser, tc.clientUser)
		})
	}
}

func basicAuthTestcase(t *testing.T, upstreamUser, clientUser *url.Userinfo) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()

		if ok {
			if _, err := w.Write([]byte(u)); err != nil {
				log.Println("[ERROR] failed to write bytes: ", err)
			}
		}
		if ok && p != "" {
			if _, err := w.Write([]byte(":")); err != nil {
				log.Println("[ERROR] failed to write bytes: ", err)
			}
			if _, err := w.Write([]byte(p)); err != nil {
				log.Println("[ERROR] failed to write bytes: ", err)
			}
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
		Upstreams: []Upstream{newFakeUpstream(backURL.String(), false, 30*time.Second, 300*time.Millisecond)},
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

	if _, err := p.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}

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

func TestProxyDirectorURL(t *testing.T) {
	for i, c := range []struct {
		requestURL string
		targetURL  string
		without    string
		expectURL  string
	}{
		{
			requestURL: `http://localhost:2020/test`,
			targetURL:  `https://localhost:2021`,
			expectURL:  `https://localhost:2021/test`,
		},
		{
			requestURL: `http://localhost:2020/test`,
			targetURL:  `https://localhost:2021/t`,
			expectURL:  `https://localhost:2021/t/test`,
		},
		{
			requestURL: `http://localhost:2020/test?t=w`,
			targetURL:  `https://localhost:2021/t`,
			expectURL:  `https://localhost:2021/t/test?t=w`,
		},
		{
			requestURL: `http://localhost:2020/test`,
			targetURL:  `https://localhost:2021/t?foo=bar`,
			expectURL:  `https://localhost:2021/t/test?foo=bar`,
		},
		{
			requestURL: `http://localhost:2020/test?t=w`,
			targetURL:  `https://localhost:2021/t?foo=bar`,
			expectURL:  `https://localhost:2021/t/test?foo=bar&t=w`,
		},
		{
			requestURL: `http://localhost:2020/test?t=w`,
			targetURL:  `https://localhost:2021/t?foo=bar`,
			expectURL:  `https://localhost:2021/t?foo=bar&t=w`,
			without:    "/test",
		},
		{
			requestURL: `http://localhost:2020/test?t%3dw`,
			targetURL:  `https://localhost:2021/t?foo%3dbar`,
			expectURL:  `https://localhost:2021/t?foo%3dbar&t%3dw`,
			without:    "/test",
		},
		{
			requestURL: `http://localhost:2020/test/`,
			targetURL:  `https://localhost:2021/t/`,
			expectURL:  `https://localhost:2021/t/test/`,
		},
		{
			requestURL: `http://localhost:2020/test/mypath`,
			targetURL:  `https://localhost:2021/t/`,
			expectURL:  `https://localhost:2021/t/mypath`,
			without:    "/test",
		},
		{
			requestURL: `http://localhost:2020/%2C`,
			targetURL:  `https://localhost:2021/t/`,
			expectURL:  `https://localhost:2021/t/%2C`,
		},
		{
			requestURL: `http://localhost:2020/%2C/`,
			targetURL:  `https://localhost:2021/t/`,
			expectURL:  `https://localhost:2021/t/%2C/`,
		},
		{
			requestURL: `http://localhost:2020/test`,
			targetURL:  `https://localhost:2021/%2C`,
			expectURL:  `https://localhost:2021/%2C/test`,
		},
		{
			requestURL: `http://localhost:2020/%2C`,
			targetURL:  `https://localhost:2021/%2C`,
			expectURL:  `https://localhost:2021/%2C/%2C`,
		},
		{
			requestURL: `http://localhost:2020/%2F/test`,
			targetURL:  `https://localhost:2021/`,
			expectURL:  `https://localhost:2021/%2F/test`,
		},
		{
			requestURL: `http://localhost:2020/test/%2F/mypath`,
			targetURL:  `https://localhost:2021/t/`,
			expectURL:  `https://localhost:2021/t/%2F/mypath`,
			without:    "/test",
		},
	} {
		targetURL, err := url.Parse(c.targetURL)
		if err != nil {
			t.Errorf("case %d failed to parse target URL: %s", i, err)
			continue
		}
		req, err := http.NewRequest("GET", c.requestURL, nil)
		if err != nil {
			t.Errorf("case %d failed to create request: %s", i, err)
			continue
		}

		NewSingleHostReverseProxy(targetURL, c.without, 0, 30*time.Second, 300*time.Millisecond).Director(req)
		if expect, got := c.expectURL, req.URL.String(); expect != got {
			t.Errorf("case %d url not equal: expect %q, but got %q",
				i, expect, got)
		}
	}
}

func TestReverseProxyRetry(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	// set up proxy
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(w, r.Body); err != nil {
			log.Println("[ERROR] failed to copy: ", err)
		}
		r.Body.Close()
	}))
	defer backend.Close()

	su, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(`
	proxy / localhost:65535 localhost:65534 `+backend.URL+` {
		policy round_robin
		fail_timeout 5s
		max_fails 1
		try_duration 5s
		try_interval 250ms
	}
	`)), "")
	if err != nil {
		t.Fatal(err)
	}

	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: su,
	}

	// middle is required to simulate closable downstream request body
	middle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err = p.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}))
	defer middle.Close()

	testCase := "test content"
	r, err := http.NewRequest("POST", middle.URL, bytes.NewBufferString(testCase))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != testCase {
		t.Fatalf("string(b) = %s, want %s", string(b), testCase)
	}
}

func TestReverseProxyLargeBody(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	// set up proxy
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(ioutil.Discard, r.Body); err != nil {
			log.Println("[ERROR] failed to copy: ", err)
		}

		r.Body.Close()
	}))
	defer backend.Close()

	su, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(`proxy / `+backend.URL)), "")
	if err != nil {
		t.Fatal(err)
	}

	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: su,
	}

	// middle is required to simulate closable downstream request body
	middle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err = p.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}))
	defer middle.Close()

	// Our request body will be 100MB
	bodySize := uint64(100 * 1000 * 1000)

	// We want to see how much memory the proxy module requires for this request.
	// So lets record the mem stats before we start it.
	begMemStats := &runtime.MemStats{}
	runtime.ReadMemStats(begMemStats)

	r, err := http.NewRequest("POST", middle.URL, &noopReader{len: bodySize})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Finally we need the mem stats after the request is done...
	endMemstats := &runtime.MemStats{}
	runtime.ReadMemStats(endMemstats)

	// ...to calculate the total amount of allocated memory during the request.
	totalAlloc := endMemstats.TotalAlloc - begMemStats.TotalAlloc

	// If that's as much as the size of the body itself it's a serious sign that the
	// request was not "streamed" to the upstream without buffering it first.
	if totalAlloc >= bodySize {
		t.Fatalf("proxy allocated too much memory: %d bytes", totalAlloc)
	}
}

func TestCancelRequest(t *testing.T) {
	reqInFlight := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reqInFlight) // cause the client to cancel its request

		select {
		case <-time.After(10 * time.Second):
			t.Error("Handler never saw CloseNotify")
			return
		case <-w.(http.CloseNotifier).CloseNotify():
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Hello, client")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}
	}))
	defer backend.Close()

	// set up proxy
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{newFakeUpstream(backend.URL, false, 30*time.Second, 300*time.Millisecond)},
	}

	// setup request with cancel ctx
	req := httptest.NewRequest("GET", "/", nil)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)

	// wait for canceling the request
	go func() {
		<-reqInFlight
		cancel()
	}()

	rec := httptest.NewRecorder()
	status, err := p.ServeHTTP(rec, req)
	expectedStatus, expectErr := CustomStatusContextCancelled, context.Canceled
	if status != expectedStatus || err != expectErr {
		t.Errorf("expect proxy handle return status[%d] with error[%v], but got status[%d] with error[%v]",
			expectedStatus, expectErr, status, err)
	}
	if body := rec.Body.String(); body != "" {
		t.Errorf("expect a blank response, but got %q", body)
	}
}

type noopReader struct {
	len uint64
	pos uint64
}

var _ io.Reader = &noopReader{}

func (r *noopReader) Read(b []byte) (int, error) {
	if r.pos >= r.len {
		return 0, io.EOF
	}
	n := int(r.len - r.pos)
	if n > len(b) {
		n = len(b)
	}
	for i := range b[:n] {
		b[i] = 0
	}
	r.pos += uint64(n)
	return n, nil
}

func newFakeUpstream(name string, insecure bool, timeout, fallbackDelay time.Duration) *fakeUpstream {
	uri, _ := url.Parse(name)
	u := &fakeUpstream{
		name:          name,
		from:          "/",
		timeout:       timeout,
		fallbackDelay: fallbackDelay,
		host: &UpstreamHost{
			Name:         name,
			ReverseProxy: NewSingleHostReverseProxy(uri, "", http.DefaultMaxIdleConnsPerHost, timeout, fallbackDelay),
		},
	}
	if insecure {
		u.host.ReverseProxy.UseInsecureTransport()
	}
	return u
}

type fakeUpstream struct {
	name          string
	host          *UpstreamHost
	from          string
	without       string
	timeout       time.Duration
	fallbackDelay time.Duration
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
			ReverseProxy: NewSingleHostReverseProxy(uri, u.without, http.DefaultMaxIdleConnsPerHost, u.GetTimeout(), u.GetFallbackDelay()),
		}
	}
	return u.host
}

func (u *fakeUpstream) AllowedPath(requestPath string) bool { return true }
func (u *fakeUpstream) GetFallbackDelay() time.Duration     { return 300 * time.Millisecond }
func (u *fakeUpstream) GetTryDuration() time.Duration       { return 1 * time.Second }
func (u *fakeUpstream) GetTryInterval() time.Duration       { return 250 * time.Millisecond }
func (u *fakeUpstream) GetTimeout() time.Duration           { return u.timeout }
func (u *fakeUpstream) GetHostCount() int                   { return 1 }
func (u *fakeUpstream) Stop() error                         { return nil }

// newWebSocketTestProxy returns a test proxy that will
// redirect to the specified backendAddr. The function
// also sets up the rules/environment for testing WebSocket
// proxy.
func newWebSocketTestProxy(backendAddr string, insecure bool, timeout time.Duration) *Proxy {
	return &Proxy{
		Next: httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{&fakeWsUpstream{
			name:     backendAddr,
			without:  "",
			insecure: insecure,
			timeout:  timeout,
		}},
	}
}

func newPrefixedWebSocketTestProxy(backendAddr string, prefix string) *Proxy {
	return &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: []Upstream{&fakeWsUpstream{name: backendAddr, without: prefix, timeout: 30 * time.Second}},
	}
}

type fakeWsUpstream struct {
	name     string
	without  string
	insecure bool
	timeout  time.Duration
}

func (u *fakeWsUpstream) From() string {
	return "/"
}

func (u *fakeWsUpstream) Select(r *http.Request) *UpstreamHost {
	uri, _ := url.Parse(u.name)
	host := &UpstreamHost{
		Name:         u.name,
		ReverseProxy: NewSingleHostReverseProxy(uri, u.without, http.DefaultMaxIdleConnsPerHost, u.GetTimeout(), u.GetFallbackDelay()),
		UpstreamHeaders: http.Header{
			"Connection": {"{>Connection}"},
			"Upgrade":    {"{>Upgrade}"}},
	}
	if u.insecure {
		host.ReverseProxy.UseInsecureTransport()
	}
	return host
}

func (u *fakeWsUpstream) AllowedPath(requestPath string) bool { return true }
func (u *fakeWsUpstream) GetFallbackDelay() time.Duration     { return 300 * time.Millisecond }
func (u *fakeWsUpstream) GetTryDuration() time.Duration       { return 1 * time.Second }
func (u *fakeWsUpstream) GetTryInterval() time.Duration       { return 250 * time.Millisecond }
func (u *fakeWsUpstream) GetTimeout() time.Duration           { return u.timeout }
func (u *fakeWsUpstream) GetHostCount() int                   { return 1 }
func (u *fakeWsUpstream) Stop() error                         { return nil }

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

// testResponseRecorder wraps `httptest.ResponseRecorder`,
// also implements `http.CloseNotifier`, `http.Hijacker` and `http.Pusher`.
type testResponseRecorder struct {
	*httpserver.ResponseWriterWrapper
}

func (testResponseRecorder) CloseNotify() <-chan bool { return nil }

// Interface guards
var _ httpserver.HTTPInterfaces = testResponseRecorder{}

func BenchmarkProxy(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Hello, client")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}
	}))
	defer backend.Close()

	upstream := newFakeUpstream(backend.URL, false, 30*time.Second, 300*time.Millisecond)
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
		if _, err := p.ServeHTTP(w, r); err != nil {
			log.Println("[ERROR] failed to serve HTTP: ", err)
		}
	}
}

func TestChunkedWebSocketReverseProxy(t *testing.T) {
	s := websocket.Server{
		Handler: websocket.Handler(func(ws *websocket.Conn) {
			for {
				select {}
			}
		}),
	}
	s.Config.Header = http.Header(make(map[string][]string))
	s.Config.Header.Set("Transfer-Encoding", "chunked")

	wsNop := httptest.NewServer(s)
	defer wsNop.Close()

	// Get proxy to use for the test
	p := newWebSocketTestProxy(wsNop.URL, false, 30*time.Second)

	// Create client request
	r := httptest.NewRequest("GET", "/", nil)

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
	_, err := p.ServeHTTP(w, r)

	// Make sure the backend accepted the WS connection.
	// Mostly interested in the Upgrade and Connection response headers
	// and the 101 status code.
	expected := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\nTransfer-Encoding: chunked\r\n\r\n")
	actual := w.fakeConn.writeBuf.Bytes()
	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected backend to accept response:\n'%s'\nActually got:\n'%s'", expected, actual)
	}

	if err != nil {
		t.Error(err)
	}
}

func TestQuic(t *testing.T) {
	if strings.ToLower(os.Getenv("CI")) != "true" {
		// TODO. (#1782) This test requires configuring hosts
		// file and updating the certificate in testdata. We
		// should find a more robust way of testing this.
		return
	}

	upstream := "quic.clemente.io:8086"
	config := "proxy / quic://" + upstream + " {\n\tinsecure_skip_verify\n}"
	content := "Hello, client"

	// make proxy
	upstreams, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(config)), "")
	if err != nil {
		t.Errorf("Expected no error. Got: %s", err.Error())
	}
	p := &Proxy{
		Next:      httpserver.EmptyNext, // prevents panic in some cases when test fails
		Upstreams: upstreams,
	}

	// start QUIC server
	go func() {
		dir, err := os.Getwd()
		if err != nil {
			t.Errorf("Expected no error. Got: %s", err.Error())
			return
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write([]byte(content)); err != nil {
				log.Println("[ERROR] failed to write bytes: ", err)
			}
			w.WriteHeader(200)
		})
		err = h2quic.ListenAndServeQUIC(
			upstream,
			path.Join(dir, "testdata", "fullchain.pem"), // TODO: Use a dynamically-generated, self-signed cert instead
			path.Join(dir, "testdata", "privkey.pem"),
			handler,
		)
		if err != nil {
			t.Errorf("Expected no error. Got: %s", err.Error())
			return
		}
	}()

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	_, err = p.ServeHTTP(w, r)
	if err != nil {
		t.Errorf("Expected no error. Got: %s", err.Error())
		return
	}

	// check response
	if w.Code != 200 {
		t.Errorf("Expected response code 200, got: %d", w.Code)
	}
	responseContent := string(w.Body.Bytes())
	if responseContent != content {
		t.Errorf("Expected response body, got: %s", responseContent)
	}
}
