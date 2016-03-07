package https

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestCallbackNoOp(t *testing.T) {
	// try base paths that aren't handled by this handler
	for _, url := range []string{
		"http://localhost/",
		"http://localhost/foo.html",
		"http://localhost/.git",
		"http://localhost/.well-known/",
		"http://localhost/.well-known/acme-challenging",
	} {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("Could not craft request, got error: %v", err)
		}
		rw := httptest.NewRecorder()
		if RequestCallback(rw, req) {
			t.Errorf("Got true with this URL, but shouldn't have: %s", url)
		}
	}
}

func TestRequestCallbackSuccess(t *testing.T) {
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
	ln, err := net.Listen("tcp", "127.0.0.1:"+AlternatePort)
	if err != nil {
		t.Fatalf("Unable to start test server listener: %v", err)
	}
	ts.Listener = ln

	// Start our engines and run the test
	ts.Start()
	defer ts.Close()
	req, err := http.NewRequest("GET", "http://127.0.0.1:"+AlternatePort+expectedPath, nil)
	if err != nil {
		t.Fatalf("Could not craft request, got error: %v", err)
	}
	rw := httptest.NewRecorder()

	RequestCallback(rw, req)

	if !proxySuccess {
		t.Fatal("Expected request to be proxied, but it wasn't")
	}
}
