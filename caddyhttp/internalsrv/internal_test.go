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

package internalsrv

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"strconv"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

const (
	internalProtectedData  = "~~~protected-data~~~"
	contentTypeOctetStream = "application/octet-stream"
)

func TestInternal(t *testing.T) {
	im := Internal{
		Next:  httpserver.HandlerFunc(internalTestHandlerFunc),
		Paths: []string{"/internal"},
	}

	tests := []struct {
		url          string
		expectedCode int
		expectedBody string
	}{
		{"/internal", http.StatusNotFound, ""},

		{"/public", 0, "/public"},
		{"/public/internal", 0, "/public/internal"},

		{"/redirect", 0, "/internal"},

		{"/cycle", http.StatusInternalServerError, ""},
	}

	var i int
	for i, test := range tests {
		req, err := http.NewRequest("GET", test.url, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		code, _ := im.ServeHTTP(rec, req)

		if code != test.expectedCode {
			t.Errorf("Test %d: Expected status code %d for %s, but got %d",
				i, test.expectedCode, test.url, code)
		}
		if rec.Body.String() != test.expectedBody {
			t.Errorf("Test %d: Expected body '%s' for %s, but got '%s'",
				i, test.expectedBody, test.url, rec.Body.String())
		}
	}

	{
		req, err := http.NewRequest("GET", "/download", nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		code, _ := im.ServeHTTP(rec, req)

		if code != 0 {
			t.Errorf("Test %d: Expected status code %d for %s, but got %d",
				i, 0, "/download", code)
		}
		if rec.Body.String() != internalProtectedData {
			t.Errorf("Test %d: Expected body '%s' for %s, but got '%s'",
				i, internalProtectedData, "/download", rec.Body.String())
		}
		contentLength, err := strconv.Atoi(rec.Header().Get("Content-Length"))
		if err != nil || contentLength != len(internalProtectedData) {
			t.Errorf("Test %d: Expected content-length %d for %s, but got %d",
				i, len(internalProtectedData), "/download", contentLength)
		}
		if val := rec.Header().Get("Content-Type"); val != contentTypeOctetStream {
			t.Errorf("Test %d: Expected content-type '%s' header for %s, but got '%s'",
				i, contentTypeOctetStream, "/download", val)
		}
		if val := rec.Header().Get("Content-Disposition"); val == "" {
			t.Errorf("Test %d: Expected content-disposition header for %s",
				i, "/download")
		}
		if val := rec.Header().Get("Content-Encoding"); val != "" {
			t.Errorf("Test %d: Expected removal of content-encoding header for %s",
				i, "/download")
		}
	}
}

func internalTestHandlerFunc(w http.ResponseWriter, r *http.Request) (int, error) {
	switch r.URL.Path {
	case "/redirect":
		w.Header().Set("X-Accel-Redirect", "/internal")

	case "/cycle":
		w.Header().Set("X-Accel-Redirect", "/cycle")

	case "/download":
		w.Header().Set("X-Accel-Redirect", "/internal/data")
		w.Header().Set("Content-Disposition", "attachment; filename=test")
		w.Header().Set("Content-Encoding", "magic")
		w.Header().Set("Content-Length", "999")

	case "/internal/data":
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", contentTypeOctetStream)
		w.Header().Set("Content-Length", strconv.Itoa(len(internalProtectedData)))
		if _, err := w.Write([]byte(internalProtectedData)); err != nil {
			log.Println("[ERROR] failed to write bytes: ", err)
		}
		return 0, nil
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, r.URL.String())

	return 0, nil
}
