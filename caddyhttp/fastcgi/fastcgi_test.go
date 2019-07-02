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

package fastcgi

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestServeHTTP(t *testing.T) {
	body := "This is some test body content"

	bodyLenStr := strconv.Itoa(len(body))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to create listener for test: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		err := fcgi.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", bodyLenStr)
			_, err := w.Write([]byte(body))
			if err != nil {
				log.Printf("[ERROR] unable to write header: %v", err)
			}
		}))
		if err != nil {
			log.Printf("[ERROR] unable to start server: %v", err)
		}
	}()

	handler := Handler{
		Next:  nil,
		Rules: []Rule{{Path: "/", balancer: address(listener.Addr().String())}},
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

func TestRuleParseAddress(t *testing.T) {
	getClientTestTable := []struct {
		rule            *Rule
		expectednetwork string
		expectedaddress string
	}{
		{&Rule{balancer: address("tcp://172.17.0.1:9000")}, "tcp", "172.17.0.1:9000"},
		{&Rule{balancer: address("fastcgi://localhost:9000")}, "tcp", "localhost:9000"},
		{&Rule{balancer: address("172.17.0.15")}, "tcp", "172.17.0.15"},
		{&Rule{balancer: address("/my/unix/socket")}, "unix", "/my/unix/socket"},
		{&Rule{balancer: address("unix:/second/unix/socket")}, "unix", "/second/unix/socket"},
	}

	for _, entry := range getClientTestTable {
		addr, err := entry.rule.Address()
		if err != nil {
			t.Errorf("Unexpected error in retrieving address: %s", err.Error())
		}
		if actualnetwork, _ := parseAddress(addr); actualnetwork != entry.expectednetwork {
			t.Errorf("Unexpected network for address string %v. Got %v, expected %v", addr, actualnetwork, entry.expectednetwork)
		}
		if _, actualaddress := parseAddress(addr); actualaddress != entry.expectedaddress {
			t.Errorf("Unexpected parsed address for address string %v. Got %v, expected %v", addr, actualaddress, entry.expectedaddress)
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

	rule := Rule{
		Ext:        ".php",
		SplitPath:  ".php",
		IndexFiles: []string{"index.php"},
	}
	u, err := url.Parse("http://localhost:2015/fgci_test.php?test=foobar")
	if err != nil {
		t.Error("Unexpected error:", err.Error())
	}

	var newReq = func() *http.Request {
		r := http.Request{
			Method:     "GET",
			URL:        u,
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
			"SCRIPT_NAME":     "/fgci_test.php",
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

	// 6. Test SCRIPT_NAME includes path prefix
	r = newReq()
	ctx := context.WithValue(r.Context(), caddy.CtxKey("path_prefix"), "/test")
	r = r.WithContext(ctx)
	envExpected = newEnv()
	envExpected["SCRIPT_NAME"] = "/test/fgci_test.php"
	testBuildEnv(r, rule, fpath, envExpected)

	// 7. Test SCRIPT_NAME,SCRIPT_FILENAME do not include PATH_INFO
	fpath = "/fgci_test.php/extra/paths"
	r = newReq()
	envExpected = newEnv()
	envExpected["PATH_INFO"] = "/extra/paths"
	envExpected["SCRIPT_NAME"] = "/fgci_test.php"
	envExpected["SCRIPT_FILENAME"] = filepath.FromSlash("/fgci_test.php")
	testBuildEnv(r, rule, fpath, envExpected)

	// 8. Test REQUEST_SCHEME in env
	r = newReq()
	envExpected = newEnv()
	envExpected["REQUEST_SCHEME"] = "http"
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
		defer func() { _ = listener.Close() }()

		handler := Handler{
			Next: nil,
			Rules: []Rule{
				{
					Path:        "/",
					balancer:    address(listener.Addr().String()),
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
		go func() {
			err := fcgi.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(test.sleep)
				w.WriteHeader(http.StatusOK)
				wg.Done()
			}))
			if err != nil {
				log.Printf("[ERROR] unable to start server: %v", err)
			}
		}()

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
		defer func() { _ = listener.Close() }()

		handler := Handler{
			Next: nil,
			Rules: []Rule{
				{
					Path:        "/",
					balancer:    address(listener.Addr().String()),
					SendTimeout: test.sendTimeout,
				},
			},
		}
		r, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatalf("Test %d: Unable to create request: %v", i, err)
		}
		w := httptest.NewRecorder()

		go func() {
			err := fcgi.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			if err != nil {
				log.Printf("[ERROR] unable to start server: %v", err)
			}
		}()

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

func TestBalancer(t *testing.T) {
	tests := [][]string{
		{"localhost", "host.local"},
		{"localhost"},
		{"localhost", "host.local", "example.com"},
		{"localhost", "host.local", "example.com", "127.0.0.1"},
	}
	for i, test := range tests {
		b := address(test...)
		for _, host := range test {
			a, err := b.Address()
			if err != nil {
				t.Errorf("Unexpected error in trying to retrieve address: %s", err.Error())
			}
			if a != host {
				t.Errorf("Test %d: expected %s, found %s", i, host, a)
			}
		}
	}
}

func address(addresses ...string) balancer {
	return &roundRobin{
		addresses: addresses,
		index:     -1,
	}
}
