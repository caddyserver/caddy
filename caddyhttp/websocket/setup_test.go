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

package websocket

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestWebSocket(t *testing.T) {
	c := caddy.NewTestController("http", `websocket cat`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(WebSocket)

	if !ok {
		t.Fatalf("Expected handler to be type WebSocket, got: %#v", handler)
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
		expectedWebSocketConfig []Config
	}{
		{`websocket /api1 cat`, false, []Config{{
			Path:    "/api1",
			Command: "cat",
		}}},

		{`websocket /api3 cat  
		  websocket /api4 cat `, false, []Config{{
			Path:    "/api3",
			Command: "cat",
		}, {
			Path:    "/api4",
			Command: "cat",
		}}},

		{`websocket /api5 "cmd arg1 arg2 arg3"`, false, []Config{{
			Path:      "/api5",
			Command:   "cmd",
			Arguments: []string{"arg1", "arg2", "arg3"},
		}}},

		// accept respawn
		{`websocket /api6 cat {
			respawn
		}`, false, []Config{{
			Path:    "/api6",
			Command: "cat",
		}}},

		// invalid configuration
		{`websocket /api7 cat {
			invalid
		}`, true, []Config{}},
	}
	for i, test := range tests {
		c := caddy.NewTestController("http", test.inputWebSocketConfig)
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
