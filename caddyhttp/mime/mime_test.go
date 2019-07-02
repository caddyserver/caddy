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

package mime

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestMimeHandler(t *testing.T) {
	mimes := Config{
		".html": "text/html",
		".txt":  "text/plain",
		".swf":  "application/x-shockwave-flash",
	}

	m := Mime{Configs: mimes}

	w := httptest.NewRecorder()
	exts := []string{
		".html", ".txt", ".swf",
	}
	for _, e := range exts {
		url := "/file" + e
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		m.Next = nextFunc(true, mimes[e])
		_, err = m.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}

	w = httptest.NewRecorder()
	exts = []string{
		".htm1", ".abc", ".mdx",
	}
	for _, e := range exts {
		url := "/file" + e
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		m.Next = nextFunc(false, "")
		_, err = m.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func nextFunc(shouldMime bool, contentType string) httpserver.Handler {
	return httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
		if shouldMime {
			if w.Header().Get("Content-Type") != contentType {
				return 0, fmt.Errorf("expected Content-Type: %v, found %v", contentType, w.Header().Get("Content-Type"))
			}
			return 0, nil
		}
		if w.Header().Get("Content-Type") != "" {
			return 0, fmt.Errorf("Content-Type header not expected")
		}
		return 0, nil
	})
}
