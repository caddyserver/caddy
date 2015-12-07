package gzip

import (
	"compress/gzip"
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestLengthFilter(t *testing.T) {
	var filters []ResponseFilter = []ResponseFilter{
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
			if filter.ShouldCompress(r) != ts.shouldCompress[j] {
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
	for i, ts := range tests {
		w := httptest.NewRecorder()
		w.Header().Set("Content-Length", fmt.Sprint(len(ts.body)))
		gz := gzipResponseWriter{gzip.NewWriter(w), w}
		rw := NewResponseFilterWriter(filters, gz)
		rw.Write([]byte(ts.body))
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
