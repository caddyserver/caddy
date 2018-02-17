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

package caddytls

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPChallengeHandlerNoOp(t *testing.T) {
	namesObtaining.Add([]string{"localhost"})

	// try base paths and host names that aren't
	// handled by this handler
	for _, url := range []string{
		"http://localhost/",
		"http://localhost/foo.html",
		"http://localhost/.git",
		"http://localhost/.well-known/",
		"http://localhost/.well-known/acme-challenging",
		"http://other/.well-known/acme-challenge/foo",
	} {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("Could not craft request, got error: %v", err)
		}
		rw := httptest.NewRecorder()
		if HTTPChallengeHandler(rw, req, "") {
			t.Errorf("Got true with this URL, but shouldn't have: %s", url)
		}
	}
}

func TestHTTPChallengeHandlerSuccess(t *testing.T) {
	expectedPath := challengeBasePath + "/asdf"

	// Set up fake acme handler backend to make sure proxying succeeds
	var proxySuccess bool
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxySuccess = true
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path '%s' but got '%s' instead", expectedPath, r.URL.Path)
		}
	}))

	// Custom listener that uses the port we expect
	ln, err := net.Listen("tcp", "127.0.0.1:"+DefaultHTTPAlternatePort)
	if err != nil {
		t.Fatalf("Unable to start test server listener: %v", err)
	}
	ts.Listener = ln

	// Tell this package that we are handling a challenge for 127.0.0.1
	namesObtaining.Add([]string{"127.0.0.1"})

	// Start our engines and run the test
	ts.Start()
	defer ts.Close()
	req, err := http.NewRequest("GET", "http://127.0.0.1:"+DefaultHTTPAlternatePort+expectedPath, nil)
	if err != nil {
		t.Fatalf("Could not craft request, got error: %v", err)
	}
	rw := httptest.NewRecorder()

	HTTPChallengeHandler(rw, req, "")

	if !proxySuccess {
		t.Fatal("Expected request to be proxied, but it wasn't")
	}
}
