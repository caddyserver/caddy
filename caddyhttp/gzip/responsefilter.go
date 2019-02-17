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
	"net/http"
	"strconv"
)

// ResponseFilter determines if the response should be gzipped.
type ResponseFilter interface {
	ShouldCompress(http.ResponseWriter) bool
}

// LengthFilter is ResponseFilter for minimum content length.
type LengthFilter int64

// ShouldCompress returns if content length is greater than or
// equals to minimum length.
func (l LengthFilter) ShouldCompress(w http.ResponseWriter) bool {
	contentLength := w.Header().Get("Content-Length")
	length, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil || length == 0 {
		return false
	}
	return l != 0 && int64(l) <= length
}

// SkipCompressedFilter is ResponseFilter that will discard already compressed responses
type SkipCompressedFilter struct{}

// ShouldCompress returns true if served file is not already compressed
// encodings via https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
func (n SkipCompressedFilter) ShouldCompress(w http.ResponseWriter) bool {
	switch w.Header().Get("Content-Encoding") {
	case "gzip", "compress", "deflate", "br":
		return false
	default:
		return true
	}
}

// ResponseFilterWriter validates ResponseFilters. It writes
// gzip compressed data if ResponseFilters are satisfied or
// uncompressed data otherwise.
type ResponseFilterWriter struct {
	filters           []ResponseFilter
	shouldCompress    bool
	statusCodeWritten bool
	*gzipResponseWriter
}

// NewResponseFilterWriter creates and initializes a new ResponseFilterWriter.
func NewResponseFilterWriter(filters []ResponseFilter, gz *gzipResponseWriter) *ResponseFilterWriter {
	return &ResponseFilterWriter{filters: filters, gzipResponseWriter: gz}
}

// WriteHeader wraps underlying WriteHeader method and
// compresses if filters are satisfied.
func (r *ResponseFilterWriter) WriteHeader(code int) {
	// Determine if compression should be used or not.
	r.shouldCompress = true
	for _, filter := range r.filters {
		if !filter.ShouldCompress(r) {
			r.shouldCompress = false
			break
		}
	}

	if r.shouldCompress {
		// replace discard writer with ResponseWriter
		if gzWriter, ok := r.gzipResponseWriter.Writer().(*gzip.Writer); ok {
			gzWriter.Reset(r.ResponseWriter)
		}
		// use gzip WriteHeader to include and delete
		// necessary headers
		r.gzipResponseWriter.WriteHeader(code)
	} else {
		r.ResponseWriter.WriteHeader(code)
	}
	r.statusCodeWritten = true
}

// Write wraps underlying Write method and compresses if filters
// are satisfied
func (r *ResponseFilterWriter) Write(b []byte) (int, error) {
	if !r.statusCodeWritten {
		r.WriteHeader(http.StatusOK)
	}
	if r.shouldCompress {
		return r.gzipResponseWriter.Write(b)
	}
	return r.ResponseWriter.Write(b)
}
