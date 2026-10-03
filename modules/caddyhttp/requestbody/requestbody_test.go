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

package requestbody

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func newRequestBodySetRequest(t *testing.T) (*http.Request, *caddy.Replacer) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "https://example.com/upload", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)

	return req.WithContext(ctx), repl
}

// TestRequestBodySetKeepsUnknownPlaceholders is a regression test for the JSON
// case: a set body is user-supplied and commonly JSON, so braces the replacer
// does not recognize must survive the expansion instead of being blanked, the
// same known-placeholder policy the respond body already follows.
func TestRequestBodySetKeepsUnknownPlaceholders(t *testing.T) {
	const jsonBody = `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`

	rb := RequestBody{Set: jsonBody}

	req, _ := newRequestBodySetRequest(t)

	var gotBody string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		gotBody = string(body)
		return nil
	})

	err := rb.ServeHTTP(httptest.NewRecorder(), req, next)
	if err != nil {
		t.Fatalf("did not expect an error, but got: %v", err)
	}

	if gotBody != jsonBody {
		t.Errorf("set body was mangled by placeholder expansion: got %q, want %q", gotBody, jsonBody)
	}
}

// TestRequestBodySetStillReplacesKnownPlaceholders guards the other direction:
// keeping unknown braces intact must not stop real placeholders from being
// replaced.
func TestRequestBodySetStillReplacesKnownPlaceholders(t *testing.T) {
	rb := RequestBody{Set: `{"token":"{caddy_request_body_test_token}"}`}
	want := `{"token":"s3cret"}`

	req, repl := newRequestBodySetRequest(t)
	repl.Set("caddy_request_body_test_token", "s3cret")

	var gotBody string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		gotBody = string(body)
		return nil
	})

	err := rb.ServeHTTP(httptest.NewRecorder(), req, next)
	if err != nil {
		t.Fatalf("did not expect an error, but got: %v", err)
	}

	if gotBody != want {
		t.Errorf("known placeholder not expanded: got %q, want %q", gotBody, want)
	}
}

// TestRequestBodySetHeaderPlaceholders verifies that HTTP request header placeholders
// resolve to an empty string when absent under ReplaceKnown, and expand to the header
// value when present, so the backend never receives literal placeholder braces.
func TestRequestBodySetHeaderPlaceholders(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setBody  string
		setupReq func(req *http.Request)
		wantBody string
	}{
		{
			name:     "absent header resolves to empty string",
			setBody:  `{"api_key":"{http.request.header.X-Api-Key}"}`,
			wantBody: `{"api_key":""}`,
		},
		{
			name:    "present header resolves to value",
			setBody: `{"api_key":"{http.request.header.X-Api-Key}"}`,
			setupReq: func(req *http.Request) {
				req.Header.Set("X-Api-Key", "secret-token")
			},
			wantBody: `{"api_key":"secret-token"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rb := RequestBody{Set: tc.setBody}

			req := httptest.NewRequest(http.MethodPost, "https://example.com/upload", nil)
			if tc.setupReq != nil {
				tc.setupReq(req)
			}
			_ = caddyhttp.NewTestReplacer(req)

			var gotBody string
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return err
				}
				gotBody = string(body)
				return nil
			})

			err := rb.ServeHTTP(httptest.NewRecorder(), req, next)
			if err != nil {
				t.Fatalf("did not expect an error, but got: %v", err)
			}

			if gotBody != tc.wantBody {
				t.Errorf("got %q, want %q", gotBody, tc.wantBody)
			}
		})
	}
}
