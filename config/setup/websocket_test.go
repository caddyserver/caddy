package setup

import (
	"github.com/mholt/caddy/middleware/websockets"
	"testing"
)

func TestWebSocket(t *testing.T) {

	c := NewTestController(`websocket cat`)

	mid, err := WebSocket(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(websockets.WebSockets)

	if !ok {
		t.Fatalf("Expected handler to be type WebSockets, got: %#v", handler)
	}

	if myHandler.Sockets[0].Path != "/" {
		t.Errorf("Expected / as the default Path")
	}
	if myHandler.Sockets[0].Command != "cat" {
		t.Errorf("Expected %s as the command", "cat")
	}

}
