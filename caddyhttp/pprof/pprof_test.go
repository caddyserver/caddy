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

package pprof

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestServeHTTP(t *testing.T) {
	h := Handler{
		Next: httpserver.HandlerFunc(nextHandler),
		Mux:  NewMux(),
	}

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/debug/pprof", nil)
	if err != nil {
		t.Fatal(err)
	}
	status, err := h.ServeHTTP(w, r)

	if status != 0 {
		t.Errorf("Expected status %d but got %d", 0, status)
	}
	if err != nil {
		t.Errorf("Expected nil error, but got: %v", err)
	}
	if w.Body.String() == "content" {
		t.Errorf("Expected pprof to handle request, but it didn't")
	}

	w = httptest.NewRecorder()
	r, err = http.NewRequest("GET", "/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	status, err = h.ServeHTTP(w, r)
	if status != http.StatusNotFound {
		t.Errorf("Test two: Expected status %d but got %d", http.StatusNotFound, status)
	}
	if err != nil {
		t.Errorf("Test two: Expected nil error, but got: %v", err)
	}
	if w.Body.String() != "content" {
		t.Errorf("Expected pprof to pass the request through, but it didn't; got: %s", w.Body.String())
	}
}

func nextHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, "content")
	return http.StatusNotFound, nil
}
