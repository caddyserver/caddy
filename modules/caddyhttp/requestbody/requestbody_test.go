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
	"strings"
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

func TestRequestBodyCaddyModule(t *testing.T) {
	rb := RequestBody{}
	info := rb.CaddyModule()
	if info.ID != "http.handlers.request_body" {
		t.Errorf("CaddyModule().ID = %v, want 'http.handlers.request_body'", info.ID)
	}
	if info.New == nil {
		t.Fatal("CaddyModule().New is nil")
	}
}

func TestErrorWrapperMaxBytesError(t *testing.T) {
	body := strings.NewReader("this body exceeds the limit")
	w := httptest.NewRecorder()
	limitedReader := http.MaxBytesReader(w, io.NopCloser(body), 5)
	ew := errorWrapper{limitedReader}

	buf := make([]byte, 100)
	totalRead := 0
	for {
		n, err := ew.Read(buf[totalRead:])
		totalRead += n
		if err != nil {
			httpErr, ok := err.(caddyhttp.HandlerError)
			if !ok {
				t.Fatalf("error should be caddyhttp.HandlerError, got %T: %v", err, err)
			}
			if httpErr.StatusCode != http.StatusRequestEntityTooLarge {
				t.Errorf("status code = %d, want %d", httpErr.StatusCode, http.StatusRequestEntityTooLarge)
			}
			break
		}
	}
}

func TestErrorWrapperNormalRead(t *testing.T) {
	body := strings.NewReader("hello")
	w := httptest.NewRecorder()
	limitedReader := http.MaxBytesReader(w, io.NopCloser(body), 1000)
	ew := errorWrapper{limitedReader}

	buf := make([]byte, 100)
	n, err := ew.Read(buf)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Read() = %q, want %q", string(buf[:n]), "hello")
	}
}

func TestServeHTTPMaxSize(t *testing.T) {
	rb := RequestBody{MaxSize: 5}
	body := io.NopCloser(strings.NewReader("this body is definitely longer than five bytes"))
	r := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()

	var calledNext bool
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		_ = data
		return nil
	})

	err := rb.ServeHTTP(w, r, nextHandler)
	if !calledNext {
		t.Error("next handler should have been called")
	}
	if err == nil {
		t.Error("expected error due to MaxSize exceeded")
	}
}

func TestServeHTTPNilBody(t *testing.T) {
	rb := RequestBody{MaxSize: 100}
	r := httptest.NewRequest("GET", "/", nil)
	r.Body = nil
	w := httptest.NewRecorder()

	var calledNext bool
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		return nil
	})

	err := rb.ServeHTTP(w, r, nextHandler)
	if err != nil {
		t.Fatalf("ServeHTTP() error: %v", err)
	}
	if !calledNext {
		t.Error("next handler should have been called")
	}
}

func TestServeHTTPZeroMaxSize(t *testing.T) {
	rb := RequestBody{MaxSize: 0}
	body := io.NopCloser(strings.NewReader("some body"))
	r := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()

	var bodyContent string
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		bodyContent = string(data)
		return nil
	})

	err := rb.ServeHTTP(w, r, nextHandler)
	if err != nil {
		t.Fatalf("ServeHTTP() error: %v", err)
	}
	if bodyContent != "some body" {
		t.Errorf("body = %q, want %q", bodyContent, "some body")
	}
}
