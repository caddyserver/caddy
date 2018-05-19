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

package gzip

import (
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestGzipHandler(t *testing.T) {
	pathFilter := PathFilter{make(Set)}
	badPaths := []string{"/bad", "/nogzip", "/nongzip"}
	for _, p := range badPaths {
		pathFilter.IgnoredPaths.Add(p)
	}
	extFilter := ExtFilter{make(Set)}
	for _, e := range []string{".txt", ".html", ".css", ".md"} {
		extFilter.Exts.Add(e)
	}
	gz := Gzip{Configs: []Config{
		{RequestFilters: []RequestFilter{pathFilter, extFilter}},
	}}

	w := httptest.NewRecorder()
	gz.Next = nextFunc(true)
	var exts = []string{
		".html", ".css", ".md",
	}
	for _, e := range exts {
		url := "/file" + e
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		r.Header.Set("Accept-Encoding", "gzip")
		w.Header().Set("ETag", `"2n9cd"`)
		_, err = gz.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}

		// The second pass, test if the ETag is already weak
		w.Header().Set("ETag", `W/"2n9cd"`)
		_, err = gz.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}

	w = httptest.NewRecorder()
	gz.Next = nextFunc(false)
	for _, p := range badPaths {
		for _, e := range exts {
			url := p + "/file" + e
			r, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Error(err)
			}
			r.Header.Set("Accept-Encoding", "gzip")
			_, err = gz.ServeHTTP(w, r)
			if err != nil {
				t.Error(err)
			}
		}
	}

	w = httptest.NewRecorder()
	gz.Next = nextFunc(false)
	exts = []string{
		".htm1", ".abc", ".mdx",
	}
	for _, e := range exts {
		url := "/file" + e
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		r.Header.Set("Accept-Encoding", "gzip")
		_, err = gz.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}

	// test all levels
	w = httptest.NewRecorder()
	gz.Next = nextFunc(true)
	for i := 0; i <= gzip.BestCompression; i++ {
		gz.Configs[0].Level = i
		r, err := http.NewRequest("GET", "/file.txt", nil)
		if err != nil {
			t.Error(err)
		}
		r.Header.Set("Accept-Encoding", "gzip")
		_, err = gz.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func nextFunc(shouldGzip bool) httpserver.Handler {
	return httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
		// write a relatively large text file
		b, err := ioutil.ReadFile("testdata/test.txt")
		if err != nil {
			return 500, err
		}
		if _, err := w.Write(b); err != nil {
			return 500, err
		}

		if shouldGzip {
			if w.Header().Get("Content-Encoding") != "gzip" {
				return 0, fmt.Errorf("Content-Encoding must be gzip, found %v", w.Header().Get("Content-Encoding"))
			}
			if w.Header().Get("Vary") != "Accept-Encoding" {
				return 0, fmt.Errorf("Vary must be Accept-Encoding, found %v", w.Header().Get("Vary"))
			}
			etag := w.Header().Get("ETag")
			if etag != "" && etag != `W/"2n9cd"` {
				return 0, fmt.Errorf("ETag must be converted to weak Etag, found %v", w.Header().Get("ETag"))
			}
			if _, ok := w.(*gzipResponseWriter); !ok {
				return 0, fmt.Errorf("ResponseWriter should be gzipResponseWriter, found %T", w)
			}
			if strings.Contains(w.Header().Get("Content-Type"), "application/x-gzip") {
				return 0, fmt.Errorf("Content-Type should not be gzip")
			}
			return 0, nil
		}
		if r.Header.Get("Accept-Encoding") == "" {
			return 0, fmt.Errorf("Accept-Encoding header expected")
		}
		if w.Header().Get("Content-Encoding") == "gzip" {
			return 0, fmt.Errorf("Content-Encoding must not be gzip, found gzip")
		}
		if _, ok := w.(*gzipResponseWriter); ok {
			return 0, fmt.Errorf("ResponseWriter should not be gzipResponseWriter")
		}
		return 0, nil
	})
}

func BenchmarkGzip(b *testing.B) {
	pathFilter := PathFilter{make(Set)}
	badPaths := []string{"/bad", "/nogzip", "/nongzip"}
	for _, p := range badPaths {
		pathFilter.IgnoredPaths.Add(p)
	}
	extFilter := ExtFilter{make(Set)}
	for _, e := range []string{".txt", ".html", ".css", ".md"} {
		extFilter.Exts.Add(e)
	}
	gz := Gzip{Configs: []Config{
		{
			RequestFilters: []RequestFilter{pathFilter, extFilter},
		},
	}}

	w := httptest.NewRecorder()
	gz.Next = nextFunc(true)
	url := "/file.txt"
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		b.Fatal(err)
	}
	r.Header.Set("Accept-Encoding", "gzip")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = gz.ServeHTTP(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}
