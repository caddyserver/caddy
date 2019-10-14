// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddyhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestHTTPVarReplacement(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)
	req.Host = "example.com:80"
	req.RemoteAddr = "localhost:1234"
	res := httptest.NewRecorder()
	addHTTPVarsToReplacer(repl, req, res)

	for i, tc := range []struct {
		input  string
		expect string
	}{
		{
			input:  "{http.request.scheme}",
			expect: "http",
		},
		{
			input:  "{http.request.host}",
			expect: "example.com",
		},
		{
			input:  "{http.request.port}",
			expect: "80",
		},
		{
			input:  "{http.request.hostport}",
			expect: "example.com:80",
		},
		{
			input:  "{http.request.remote.host}",
			expect: "localhost",
		},
		{
			input:  "{http.request.remote.port}",
			expect: "1234",
		},
		{
			input:  "{http.request.host.labels.0}",
			expect: "com",
		},
		{
			input:  "{http.request.host.labels.1}",
			expect: "example",
		},
	} {
		actual := repl.ReplaceAll(tc.input, "<empty>")
		if actual != tc.expect {
			t.Errorf("Test %d: Expected placeholder %s to be '%s' but got '%s'",
				i, tc.input, tc.expect, actual)
		}
	}
}
