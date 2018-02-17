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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestRequestIDHandler(t *testing.T) {
	handler := Handler{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			value, _ := r.Context().Value(httpserver.RequestIDCtxKey).(string)
			if value == "" {
				t.Error("Request ID should not be empty")
			}
			return 0, nil
		}),
	}

	req, err := http.NewRequest("GET", "http://localhost/", nil)
	if err != nil {
		t.Fatal("Could not create HTTP request:", err)
	}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
}

func TestRequestIDFromHeader(t *testing.T) {
	headerName := "X-Request-ID"
	headerValue := "71a75329-d9f9-4d25-957e-e689a7b68d78"
	handler := Handler{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			value, _ := r.Context().Value(httpserver.RequestIDCtxKey).(string)
			if value != headerValue {
				t.Errorf("Request ID should be '%s' but got '%s'", headerValue, value)
			}
			return 0, nil
		}),
		HeaderName: headerName,
	}

	req, err := http.NewRequest("GET", "http://localhost/", nil)
	if err != nil {
		t.Fatal("Could not create HTTP request:", err)
	}
	req.Header.Set(headerName, headerValue)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
}
