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

package status

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestStatus(t *testing.T) {
	status := Status{
		Rules: []httpserver.HandlerConfig{
			NewRule("/foo", http.StatusNotFound),
			NewRule("/teapot", http.StatusTeapot),
			NewRule("/foo/bar1", http.StatusInternalServerError),
			NewRule("/temporary-redirected", http.StatusTemporaryRedirect),
		},
		Next: httpserver.HandlerFunc(urlPrinter),
	}

	tests := []struct {
		path           string
		statusExpected bool
		status         int
	}{
		{"/foo", true, http.StatusNotFound},
		{"/teapot", true, http.StatusTeapot},
		{"/foo/bar", true, http.StatusNotFound},
		{"/foo/bar1", true, http.StatusInternalServerError},
		{"/someotherpath", false, 0},
		{"/temporary-redirected", false, http.StatusTemporaryRedirect},
	}

	for i, test := range tests {
		req, err := http.NewRequest("GET", test.path, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v",
				i, err)
		}

		rec := httptest.NewRecorder()
		actualStatus, err := status.ServeHTTP(rec, req)
		if err != nil {
			t.Fatalf("Test %d: Serving request failed with error %v",
				i, err)
		}

		if test.statusExpected {
			if test.status != actualStatus {
				t.Errorf("Test %d: Expected status code %d, got %d",
					i, test.status, actualStatus)
			}
			if rec.Body.String() != "" {
				t.Errorf("Test %d: Expected empty body, got '%s'",
					i, rec.Body.String())
			}
		} else {
			if test.status != 0 { // Expecting status in response
				if test.status != rec.Code {
					t.Errorf("Test %d: Expected status code %d, got %d",
						i, test.status, rec.Code)
				}
			} else if rec.Body.String() != test.path {
				t.Errorf("Test %d: Expected body '%s', got '%s'",
					i, test.path, rec.Body.String())
			}
		}
	}
}

func urlPrinter(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprint(w, r.URL.String())
	return 0, nil
}
