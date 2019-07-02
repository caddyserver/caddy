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
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestLengthFilter(t *testing.T) {
	var filters = []ResponseFilter{
		LengthFilter(100),
		LengthFilter(1000),
		LengthFilter(0),
	}

	var tests = []struct {
		length         int64
		shouldCompress [3]bool
	}{
		{20, [3]bool{false, false, false}},
		{50, [3]bool{false, false, false}},
		{100, [3]bool{true, false, false}},
		{500, [3]bool{true, false, false}},
		{1000, [3]bool{true, true, false}},
		{1500, [3]bool{true, true, false}},
	}

	for i, ts := range tests {
		for j, filter := range filters {
			r := httptest.NewRecorder()
			r.Header().Set("Content-Length", fmt.Sprint(ts.length))
			wWriter := NewResponseFilterWriter([]ResponseFilter{filter}, &gzipResponseWriter{gzip.NewWriter(r), &httpserver.ResponseWriterWrapper{ResponseWriter: r}, false, nil})
			if filter.ShouldCompress(wWriter) != ts.shouldCompress[j] {
				t.Errorf("Test %v: Expected %v found %v", i, ts.shouldCompress[j], filter.ShouldCompress(r))
			}
		}
	}
}

func TestResponseFilterWriter(t *testing.T) {
	tests := []struct {
		body           string
		shouldCompress bool
	}{
		{"Hello\t\t\t\n", false},
		{"Hello the \t\t\t world is\n\n\n great", true},
		{"Hello \t\t\nfrom gzip", true},
		{"Hello gzip\n", false},
	}

	filters := []ResponseFilter{
		LengthFilter(15),
	}

	server := Gzip{Configs: []Config{
		{ResponseFilters: filters},
	}}

	for i, ts := range tests {
		server.Next = httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			w.Header().Set("Content-Length", fmt.Sprint(len(ts.body)))
			if _, err := w.Write([]byte(ts.body)); err != nil {
				log.Println("[ERROR] failed to write response: ", err)
			}
			return 200, nil
		})

		r := urlRequest("/")
		r.Header.Set("Accept-Encoding", "gzip")

		w := httptest.NewRecorder()

		if _, err := server.ServeHTTP(w, r); err != nil {
			log.Println("[ERROR] unable to serve a gzipped response: ", err)
		}

		resp := w.Body.String()

		if !ts.shouldCompress {
			if resp != ts.body {
				t.Errorf("Test %v: No compression expected, found %v", i, resp)
			}
		} else {
			if resp == ts.body {
				t.Errorf("Test %v: Compression expected, found %v", i, resp)
			}
		}
	}
}

func TestResponseGzippedOutput(t *testing.T) {
	server := Gzip{Configs: []Config{
		{ResponseFilters: []ResponseFilter{SkipCompressedFilter{}}},
	}}

	server.Next = httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
		w.Header().Set("Content-Encoding", "gzip")
		if _, err := w.Write([]byte("gzipped")); err != nil {
			log.Println("[ERROR] failed to write response: ", err)
		}
		return 200, nil
	})

	r := urlRequest("/")
	r.Header.Set("Accept-Encoding", "gzip")

	w := httptest.NewRecorder()
	if _, err := server.ServeHTTP(w, r); err != nil {
		log.Println("[ERROR] unable to serve a gzipped response: ", err)
	}
	resp := w.Body.String()

	if resp != "gzipped" {
		t.Errorf("Expected output not to be gzipped")
	}
}
