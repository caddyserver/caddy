package httpserver

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAddress(t *testing.T) {
	addr := "127.0.0.1:9005"
	srv := &Server{Server: &http.Server{Addr: addr}}

	if got, want := srv.Address(), addr; got != want {
		t.Errorf("Expected '%s' but got '%s'", want, got)
	}
}

func TestStop(t *testing.T) {
	// Create Server
	s, err := NewServer("", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Stop(); err != nil {
		t.Error("Server errored while trying to Stop", err)
	}
}

func TestServer(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	// Create Server
	s, err := NewServer("", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Reduce connTimeout for testing
	s.connTimeout = 1 * time.Millisecond

	s.Server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	})

	// Set the test server config to the Server
	ts.Config = s.Server
	ts.Start()

	// Set listener
	s.listener = ts.Listener

	client := http.Client{}
	res, err := client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "hello" {
		t.Errorf("got %q, want hello", string(got))
	}

	// Make sure there is only 1 connection
	s.mu.Lock()
	if len(s.conns) < 1 {
		t.Fatal("Should have 1 connections")
	}
	s.mu.Unlock()

	// Stop the server
	s.Stop()

	// Try to connect to the server after it's closed
	res, err = client.Get(ts.URL)

	// This should always error because new connections are not allowed
	if err == nil {
		t.Fatal("Should not accept new connections after close")
	}

	// Make sure there are zero connections
	s.mu.Lock()
	if len(s.conns) < 0 {
		t.Fatal("Should have 0 connections")
	}
	s.mu.Unlock()
}
