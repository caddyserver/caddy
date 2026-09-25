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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestStaticResponseHandler(t *testing.T) {
	r := fakeRequest()
	w := httptest.NewRecorder()

	s := StaticResponse{
		StatusCode: WeakString(strconv.Itoa(http.StatusNotFound)),
		Headers: http.Header{
			"X-Test": []string{"Testing"},
		},
		Body:  "Text",
		Close: true,
	}

	err := s.ServeHTTP(w, r, nil)
	if err != nil {
		t.Errorf("did not expect an error, but got: %v", err)
	}

	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status %d but got %d", http.StatusNotFound, resp.StatusCode)
	}
	if resp.Header.Get("X-Test") != "Testing" {
		t.Errorf("expected x-test header to be 'testing' but was '%s'", resp.Header.Get("X-Test"))
	}
	if string(respBody) != "Text" {
		t.Errorf("expected body to be 'test' but was '%s'", respBody)
	}
}

func fakeRequest() *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)
	return r
}

func TestStaticResponseHeadersKeepUnknownPlaceholders(t *testing.T) {
	r := fakeRequest()
	w := httptest.NewRecorder()

	s := StaticResponse{
		StatusCode: WeakString(strconv.Itoa(http.StatusOK)),
		Headers: http.Header{
			"X-Json": []string{`{"key":"value"}`},
			"X-Lit":  []string{"value-{not-a-real-placeholder}-kept"},
		},
	}

	err := s.ServeHTTP(w, r, nil)
	if err != nil {
		t.Errorf("did not expect an error, but got: %v", err)
	}

	resp := w.Result()

	if got, want := resp.Header.Get("X-Json"), `{"key":"value"}`; got != want {
		t.Errorf("X-Json header = %q, want %q (unknown placeholders in header values must not be blanked)", got, want)
	}
	if got, want := resp.Header.Get("X-Lit"), "value-{not-a-real-placeholder}-kept"; got != want {
		t.Errorf("X-Lit header = %q, want %q", got, want)
	}
}

func TestStaticResponseHeadersStillReplaceKnownPlaceholders(t *testing.T) {
	r := fakeRequest()
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("testvar", "replaced")
	w := httptest.NewRecorder()

	s := StaticResponse{
		StatusCode: WeakString(strconv.Itoa(http.StatusOK)),
		Headers: http.Header{
			"X-Var": []string{"value-{testvar}-end"},
		},
	}

	err := s.ServeHTTP(w, r, nil)
	if err != nil {
		t.Errorf("did not expect an error, but got: %v", err)
	}

	if got, want := w.Result().Header.Get("X-Var"), "value-replaced-end"; got != want {
		t.Errorf("X-Var header = %q, want %q (real placeholders must still expand)", got, want)
	}
}
