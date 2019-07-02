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

package internalsrv

import (
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `internal /internal`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Internal)

	if !ok {
		t.Fatalf("Expected handler to be type Internal, got: %#v", handler)
	}

	if myHandler.Paths[0] != "/internal" {
		t.Errorf("Expected internal in the list of internal Paths")
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

}

func TestInternalParse(t *testing.T) {
	tests := []struct {
		inputInternalPaths    string
		shouldErr             bool
		expectedInternalPaths []string
	}{
		{`internal`, false, []string{}},

		{`internal /internal`, false, []string{"/internal"}},

		{`internal /internal1
		  internal /internal2`, false, []string{"/internal1", "/internal2"}},

		{`internal /internal1 /internal2`, true, nil},
	}
	for i, test := range tests {
		actualInternalPaths, err := internalParse(caddy.NewTestController("http", test.inputInternalPaths))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}

		if len(actualInternalPaths) != len(test.expectedInternalPaths) {
			t.Fatalf("Test %d expected %d InternalPaths, but got %d",
				i, len(test.expectedInternalPaths), len(actualInternalPaths))
		}
		for j, actualInternalPath := range actualInternalPaths {
			if actualInternalPath != test.expectedInternalPaths[j] {
				t.Fatalf("Test %d expected %dth Internal Path to be  %s  , but got %s",
					i, j, test.expectedInternalPaths[j], actualInternalPath)
			}
		}
	}

}
