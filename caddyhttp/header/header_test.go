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

package header

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestHeader(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("Could not determine hostname: %v", err)
	}
	for i, test := range []struct {
		from  string
		name  string
		value string
	}{
		{"/a", "Foo", "Bar"},
		{"/a", "Bar", ""},
		{"/a", "Baz", ""},
		{"/a", "Server", ""},
		{"/a", "ServerName", hostname},
		{"/b", "Foo", ""},
		{"/b", "Bar", "Removed in /a"},
	} {
		he := Headers{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				w.Header().Set("Bar", "Removed in /a")
				w.WriteHeader(http.StatusOK)
				return 0, nil
			}),
			Rules: []Rule{
				{Path: "/a", Headers: http.Header{
					"Foo":        []string{"Bar"},
					"ServerName": []string{"{hostname}"},
					"-Bar":       []string{""},
					"-Server":    []string{},
				}},
			},
		}

		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		// preset header
		rec.Header().Set("Server", "Caddy")

		if _, err := he.ServeHTTP(rec, req); err != nil {
			log.Println("[ERROR] ServeHTTP failed: ", err)
		}

		if got := rec.Header().Get(test.name); got != test.value {
			t.Errorf("Test %d: Expected %s header to be %q but was %q",
				i, test.name, test.value, got)
		}
	}
}

func TestMultipleHeaders(t *testing.T) {
	he := Headers{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			if _, err := fmt.Fprint(w, "This is a test"); err != nil {
				log.Println("[ERROR] Fprint failed: ", err)
			}
			return 0, nil
		}),
		Rules: []Rule{
			{Path: "/a", Headers: http.Header{
				"+Link": []string{"</images/image.png>; rel=preload", "</css/main.css>; rel=preload"},
			}},
		},
	}

	req, err := http.NewRequest("GET", "/a", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	rec := httptest.NewRecorder()
	if _, err := he.ServeHTTP(rec, req); err != nil {
		log.Println("[ERROR] ServeHTTP failed: ", err)
	}

	desiredHeaders := []string{"</css/main.css>; rel=preload", "</images/image.png>; rel=preload"}
	actualHeaders := rec.HeaderMap[http.CanonicalHeaderKey("Link")]
	sort.Strings(actualHeaders)

	if !reflect.DeepEqual(desiredHeaders, actualHeaders) {
		t.Errorf("Expected header to contain: %v but got: %v", desiredHeaders, actualHeaders)
	}
}
