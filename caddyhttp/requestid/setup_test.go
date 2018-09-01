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

package requestid

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `requestid`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Handler)

	if !ok {
		t.Fatalf("Expected handler to be type Handler, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestSetupWithArg(t *testing.T) {
	c := caddy.NewTestController("http", `requestid X-Request-ID`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

func TestSetupWithTooManyArgs(t *testing.T) {
	c := caddy.NewTestController("http", `requestid foo bar`)
	err := setup(c)
	if err == nil {
		t.Errorf("Expected an error, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) != 0 {
		t.Fatal("Expected no middleware")
	}
}
