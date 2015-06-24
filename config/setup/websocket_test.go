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
func TestWebSocketParse(t *testing.T) {
	tests := []struct {
		inputWebSocketConfig    string
		shouldErr               bool
		expectedWebSocketConfig []websockets.Config
	}{
		{`websocket /api1 cat`, false, []websockets.Config{{
			Path:    "/api1",
			Command: "cat",
		}}},

		{`websocket /api3 cat  
		  websocket /api4 cat `, false, []websockets.Config{{
			Path:    "/api3",
			Command: "cat",
		}, {
			Path:    "/api4",
			Command: "cat",
		}}},
	}
	for i, test := range tests {
		c := NewTestController(test.inputWebSocketConfig)
		actualWebSocketConfigs, err := webSocketParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}
		if len(actualWebSocketConfigs) != len(test.expectedWebSocketConfig) {
			t.Fatalf("Test %d expected %d no of WebSocket configs, but got %d ",
				i, len(test.expectedWebSocketConfig), len(actualWebSocketConfigs))
		}
		for j, actualWebSocketConfig := range actualWebSocketConfigs {

			if actualWebSocketConfig.Path != test.expectedWebSocketConfig[j].Path {
				t.Errorf("Test %d expected %dth WebSocket Config Path to be  %s  , but got %s",
					i, j, test.expectedWebSocketConfig[j].Path, actualWebSocketConfig.Path)
			}

			if actualWebSocketConfig.Command != test.expectedWebSocketConfig[j].Command {
				t.Errorf("Test %d expected %dth WebSocket Config Command to be  %s  , but got %s",
					i, j, test.expectedWebSocketConfig[j].Command, actualWebSocketConfig.Command)
			}

		}
	}

}
