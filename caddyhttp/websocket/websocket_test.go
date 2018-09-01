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
	"net/http"
	"testing"
)

func TestBuildEnv(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost", nil)
	if err != nil {
		t.Fatal("Error setting up request:", err)
	}
	req.RemoteAddr = "localhost:50302"

	env, err := buildEnv("/bin/command", req)
	if err != nil {
		t.Fatal("Didn't expect an error:", err)
	}
	if len(env) == 0 {
		t.Fatalf("Expected non-empty environment; got %#v", env)
	}
}
