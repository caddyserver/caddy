package gzip

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
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
			wWriter := NewResponseFilterWriter([]ResponseFilter{filter}, &gzipResponseWriter{gzip.NewWriter(r), r, false})
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
			w.Write([]byte(ts.body))
			return 200, nil
		})

		r := urlRequest("/")
		r.Header.Set("Accept-Encoding", "gzip")

		w := httptest.NewRecorder()

		server.ServeHTTP(w, r)

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
		w.Write([]byte("gzipped"))
		return 200, nil
	})

	r := urlRequest("/")
	r.Header.Set("Accept-Encoding", "gzip")

	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	resp := w.Body.String()

	if resp != "gzipped" {
		t.Errorf("Expected output not to be gzipped")
	}
}
