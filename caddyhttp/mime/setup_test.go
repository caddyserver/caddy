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

package mime

import (
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `mime .txt text/plain`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, but had 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Mime)
	if !ok {
		t.Fatalf("Expected handler to be type Mime, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`mime {`, true},
		{`mime {}`, true},
		{`mime a b`, true},
		{`mime a {`, true},
		{`mime { txt f } `, true},
		{`mime { html } `, true},
		{`mime {
		 .html text/html
		 .txt text/plain
		} `, false},
		{`mime {
		 .foo text/foo
		 .bar text/bar
		 .foo text/foobar
		} `, true},
		{`mime { .html text/html } `, false},
		{`mime { .html
		} `, true},
		{`mime .txt text/plain`, false},
	}
	for i, test := range tests {
		m, err := mimeParse(caddy.NewTestController("http", test.input))
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil %v", i, m)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}
