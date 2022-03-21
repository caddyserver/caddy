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
	r, _ = PrepareRequest(r, repl, httptest.NewRecorder(), nil)
	return r
}
