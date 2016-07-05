package httpserver

import (
	"net/http"
	"testing"
)

func TestAddress(t *testing.T) {
	addr := "127.0.0.1:9005"
	srv := &Server{Server: &http.Server{Addr: addr}}

	if got, want := srv.Address(), addr; got != want {
		t.Errorf("Expected '%s' but got '%s'", want, got)
	}
}
