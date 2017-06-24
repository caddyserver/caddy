package fastcgi

import (
	"context"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestServeHTTP(t *testing.T) {
	body := "This is some test body content"

	bodyLenStr := strconv.Itoa(len(body))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to create listener for test: %v", err)
	}
	defer listener.Close()
	go fcgi.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", bodyLenStr)
		w.Write([]byte(body))
	}))

	network, address := parseAddress(listener.Addr().String())
	handler := Handler{
		Next: nil,
		Rules: []Rule{
			{
				Path:    "/",
				Address: listener.Addr().String(),
				dialer:  basicDialer{network: network, address: address},
			},
		},
	}
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Unable to create request: %v", err)
	}
	w := httptest.NewRecorder()

	status, err := handler.ServeHTTP(w, r)

	if got, want := status, 0; got != want {
		t.Errorf("Expected returned status code to be %d, got %d", want, got)
	}
	if err != nil {
		t.Errorf("Expected nil error, got: %v", err)
	}
	if got, want := w.Header().Get("Content-Length"), bodyLenStr; got != want {
		t.Errorf("Expected Content-Length to be '%s', got: '%s'", want, got)
	}
	if got, want := w.Body.String(), body; got != want {
		t.Errorf("Expected response body to be '%s', got: '%s'", want, got)
	}
}

// connectionCounter in fact is a listener with an added counter to keep track
// of the number of accepted connections.
type connectionCounter struct {
	net.Listener
	sync.Mutex
	counter int
}

func (l *connectionCounter) Accept() (net.Conn, error) {
	l.Lock()
	l.counter++
	l.Unlock()
	return l.Listener.Accept()
}

// TestPersistent ensures that persistent
// as well as the non-persistent fastCGI servers
// send the answers corresnponding to the correct request.
// It also checks the number of tcp connections used.
func TestPersistent(t *testing.T) {
	numberOfRequests := 32

	for _, poolsize := range []int{0, 1, 5, numberOfRequests} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Unable to create listener for test: %v", err)
		}

		listener := &connectionCounter{l, *new(sync.Mutex), 0}

		// this fcgi server replies with the request URL
		go fcgi.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := "This answers a request to " + r.URL.Path
			bodyLenStr := strconv.Itoa(len(body))

			w.Header().Set("Content-Length", bodyLenStr)
			w.Write([]byte(body))
		}))

		network, address := parseAddress(listener.Addr().String())
		handler := Handler{
			Next:  nil,
			Rules: []Rule{{Path: "/", Address: listener.Addr().String(), dialer: &persistentDialer{size: poolsize, network: network, address: address}}},
		}

		var semaphore sync.WaitGroup
		serialMutex := new(sync.Mutex)

		serialCounter := 0
		parallelCounter := 0
		// make some serial followed by some
		// parallel requests to challenge the handler
		for _, serialize := range []bool{true, false, false, false} {
			if serialize {
				serialCounter++
			} else {
				parallelCounter++
			}
			semaphore.Add(numberOfRequests)

			for i := 0; i < numberOfRequests; i++ {
				go func(i int, serialize bool) {
					defer semaphore.Done()
					if serialize {
						serialMutex.Lock()
						defer serialMutex.Unlock()
					}
					r, err := http.NewRequest("GET", "/"+strconv.Itoa(i), nil)
					if err != nil {
						t.Errorf("Unable to create request: %v", err)
					}
					ctx := context.WithValue(r.Context(), httpserver.OriginalURLCtxKey, *r.URL)
					r = r.WithContext(ctx)
					w := httptest.NewRecorder()

					status, err := handler.ServeHTTP(w, r)

					if status != 0 {
						t.Errorf("Handler(pool: %v) return status %v", poolsize, status)
					}
					if err != nil {
						t.Errorf("Handler(pool: %v) Error: %v", poolsize, err)
					}
					want := "This answers a request to /" + strconv.Itoa(i)
					if got := w.Body.String(); got != want {
						t.Errorf("Expected response from handler(pool: %v) to be '%s', got: '%s'", poolsize, want, got)
					}
				}(i, serialize)
			} //next request
			semaphore.Wait()
		} // next set of requests (serial/parallel)

		listener.Close()
		t.Logf("The pool: %v test used %v tcp connections to answer %v * %v serial and %v * %v parallel requests.", poolsize, listener.counter, serialCounter, numberOfRequests, parallelCounter, numberOfRequests)
	} // next handler (persistent/non-persistent)
}

func TestRuleParseAddress(t *testing.T) {
	getClientTestTable := []struct {
		rule            *Rule
		expectednetwork string
		expectedaddress string
	}{
		{&Rule{Address: "tcp://172.17.0.1:9000"}, "tcp", "172.17.0.1:9000"},
		{&Rule{Address: "fastcgi://localhost:9000"}, "tcp", "localhost:9000"},
		{&Rule{Address: "172.17.0.15"}, "tcp", "172.17.0.15"},
		{&Rule{Address: "/my/unix/socket"}, "unix", "/my/unix/socket"},
		{&Rule{Address: "unix:/second/unix/socket"}, "unix", "/second/unix/socket"},
	}

	for _, entry := range getClientTestTable {
		if actualnetwork, _ := parseAddress(entry.rule.Address); actualnetwork != entry.expectednetwork {
			t.Errorf("Unexpected network for address string %v. Got %v, expected %v", entry.rule.Address, actualnetwork, entry.expectednetwork)
		}
		if _, actualaddress := parseAddress(entry.rule.Address); actualaddress != entry.expectedaddress {
			t.Errorf("Unexpected parsed address for address string %v. Got %v, expected %v", entry.rule.Address, actualaddress, entry.expectedaddress)
		}
	}
}

func TestRuleIgnoredPath(t *testing.T) {
	rule := &Rule{
		Path:            "/fastcgi",
		IgnoredSubPaths: []string{"/download", "/static"},
	}
	tests := []struct {
		url      string
		expected bool
	}{
		{"/fastcgi", true},
		{"/fastcgi/dl", true},
		{"/fastcgi/download", false},
		{"/fastcgi/download/static", false},
		{"/fastcgi/static", false},
		{"/fastcgi/static/download", false},
		{"/fastcgi/something/download", true},
		{"/fastcgi/something/static", true},
		{"/fastcgi//static", false},
		{"/fastcgi//static//download", false},
		{"/fastcgi//download", false},
	}

	for i, test := range tests {
		allowed := rule.AllowedPath(test.url)
		if test.expected != allowed {
			t.Errorf("Test %d: expected %v found %v", i, test.expected, allowed)
		}
	}
}

func TestBuildEnv(t *testing.T) {
	testBuildEnv := func(r *http.Request, rule Rule, fpath string, envExpected map[string]string) {
		var h Handler
		env, err := h.buildEnv(r, rule, fpath)
		if err != nil {
			t.Error("Unexpected error:", err.Error())
		}
		for k, v := range envExpected {
			if env[k] != v {
				t.Errorf("Unexpected %v. Got %v, expected %v", k, env[k], v)
			}
		}
	}

	rule := Rule{}
	url, err := url.Parse("http://localhost:2015/fgci_test.php?test=foobar")
	if err != nil {
		t.Error("Unexpected error:", err.Error())
	}

	var newReq = func() *http.Request {
		r := http.Request{
			Method:     "GET",
			URL:        url,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Host:       "localhost:2015",
			RemoteAddr: "[2b02:1810:4f2d:9400:70ab:f822:be8a:9093]:51688",
			RequestURI: "/fgci_test.php",
			Header: map[string][]string{
				"Foo": {"Bar", "two"},
			},
		}
		ctx := context.WithValue(r.Context(), httpserver.OriginalURLCtxKey, *r.URL)
		return r.WithContext(ctx)
	}

	fpath := "/fgci_test.php"

	var newEnv = func() map[string]string {
		return map[string]string{
			"REMOTE_ADDR":     "2b02:1810:4f2d:9400:70ab:f822:be8a:9093",
			"REMOTE_PORT":     "51688",
			"SERVER_PROTOCOL": "HTTP/1.1",
			"QUERY_STRING":    "test=foobar",
			"REQUEST_METHOD":  "GET",
			"HTTP_HOST":       "localhost:2015",
		}
	}

	// request
	var r *http.Request

	// expected environment variables
	var envExpected map[string]string

	// 1. Test for full canonical IPv6 address
	r = newReq()
	testBuildEnv(r, rule, fpath, envExpected)

	// 2. Test for shorthand notation of IPv6 address
	r = newReq()
	r.RemoteAddr = "[::1]:51688"
	envExpected = newEnv()
	envExpected["REMOTE_ADDR"] = "::1"
	testBuildEnv(r, rule, fpath, envExpected)

	// 3. Test for IPv4 address
	r = newReq()
	r.RemoteAddr = "192.168.0.10:51688"
	envExpected = newEnv()
	envExpected["REMOTE_ADDR"] = "192.168.0.10"
	testBuildEnv(r, rule, fpath, envExpected)

	// 4. Test for environment variable
	r = newReq()
	rule.EnvVars = [][2]string{
		{"HTTP_HOST", "localhost:2016"},
		{"REQUEST_METHOD", "POST"},
	}
	envExpected = newEnv()
	envExpected["HTTP_HOST"] = "localhost:2016"
	envExpected["REQUEST_METHOD"] = "POST"
	testBuildEnv(r, rule, fpath, envExpected)

	// 5. Test for environment variable placeholders
	r = newReq()
	rule.EnvVars = [][2]string{
		{"HTTP_HOST", "{host}"},
		{"CUSTOM_URI", "custom_uri{uri}"},
		{"CUSTOM_QUERY", "custom=true&{query}"},
	}
	envExpected = newEnv()
	envExpected["HTTP_HOST"] = "localhost:2015"
	envExpected["CUSTOM_URI"] = "custom_uri/fgci_test.php?test=foobar"
	envExpected["CUSTOM_QUERY"] = "custom=true&test=foobar"
	testBuildEnv(r, rule, fpath, envExpected)
}

func TestReadTimeout(t *testing.T) {
	tests := []struct {
		sleep       time.Duration
		readTimeout time.Duration
		shouldErr   bool
	}{
		{75 * time.Millisecond, 50 * time.Millisecond, true},
		{0, -1 * time.Second, true},
		{0, time.Minute, false},
	}

	var wg sync.WaitGroup

	for i, test := range tests {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Test %d: Unable to create listener for test: %v", i, err)
		}
		defer listener.Close()

		network, address := parseAddress(listener.Addr().String())
		handler := Handler{
			Next: nil,
			Rules: []Rule{
				{
					Path:        "/",
					Address:     listener.Addr().String(),
					dialer:      basicDialer{network: network, address: address},
					ReadTimeout: test.readTimeout,
				},
			},
		}
		r, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatalf("Test %d: Unable to create request: %v", i, err)
		}
		w := httptest.NewRecorder()

		wg.Add(1)
		go fcgi.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(test.sleep)
			w.WriteHeader(http.StatusOK)
			wg.Done()
		}))

		got, err := handler.ServeHTTP(w, r)
		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %d: Expected i/o timeout error but had none", i)
			} else if err, ok := err.(net.Error); !ok || !err.Timeout() {
				t.Errorf("Test %d: Expected i/o timeout error, got: '%s'", i, err.Error())
			}

			want := http.StatusGatewayTimeout
			if got != want {
				t.Errorf("Test %d: Expected returned status code to be %d, got: %d",
					i, want, got)
			}
		} else if err != nil {
			t.Errorf("Test %d: Expected nil error, got: %v", i, err)
		}

		wg.Wait()
	}
}

func TestSendTimeout(t *testing.T) {
	tests := []struct {
		sendTimeout time.Duration
		shouldErr   bool
	}{
		{-1 * time.Second, true},
		{time.Minute, false},
	}

	for i, test := range tests {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Test %d: Unable to create listener for test: %v", i, err)
		}
		defer listener.Close()

		network, address := parseAddress(listener.Addr().String())
		handler := Handler{
			Next: nil,
			Rules: []Rule{
				{
					Path:        "/",
					Address:     listener.Addr().String(),
					dialer:      basicDialer{network: network, address: address},
					SendTimeout: test.sendTimeout,
				},
			},
		}
		r, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatalf("Test %d: Unable to create request: %v", i, err)
		}
		w := httptest.NewRecorder()

		go fcgi.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		got, err := handler.ServeHTTP(w, r)
		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %d: Expected i/o timeout error but had none", i)
			} else if err, ok := err.(net.Error); !ok || !err.Timeout() {
				t.Errorf("Test %d: Expected i/o timeout error, got: '%s'", i, err.Error())
			}

			want := http.StatusGatewayTimeout
			if got != want {
				t.Errorf("Test %d: Expected returned status code to be %d, got: %d",
					i, want, got)
			}
		} else if err != nil {
			t.Errorf("Test %d: Expected nil error, got: %v", i, err)
		}
	}
}
