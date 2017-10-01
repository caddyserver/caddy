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

package extensions

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `ext .html .htm .php`)
	err := setup(c)
	if err != nil {
		t.Fatalf("Expected no errors, got: %v", err)
	}

	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, had 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Ext)

	if !ok {
		t.Fatalf("Expected handler to be type Ext, got: %#v", handler)
	}

	if myHandler.Extensions[0] != ".html" {
		t.Errorf("Expected .html in the list of Extensions")
	}
	if myHandler.Extensions[1] != ".htm" {
		t.Errorf("Expected .htm in the list of Extensions")
	}
	if myHandler.Extensions[2] != ".php" {
		t.Errorf("Expected .php in the list of Extensions")
	}
	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

}

func TestExtParse(t *testing.T) {
	tests := []struct {
		inputExts    string
		shouldErr    bool
		expectedExts []string
	}{
		{`ext .html .htm .php`, false, []string{".html", ".htm", ".php"}},
		{`ext .php .html .xml`, false, []string{".php", ".html", ".xml"}},
		{`ext .txt .php .xml`, false, []string{".txt", ".php", ".xml"}},
	}
	for i, test := range tests {
		actualExts, err := extParse(caddy.NewTestController("http", test.inputExts))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}

		if len(actualExts) != len(test.expectedExts) {
			t.Fatalf("Test %d expected %d rules, but got %d",
				i, len(test.expectedExts), len(actualExts))
		}
		for j, actualExt := range actualExts {
			if actualExt != test.expectedExts[j] {
				t.Fatalf("Test %d expected %dth extension to be  %s  , but got %s",
					i, j, test.expectedExts[j], actualExt)
			}
		}
	}

}
