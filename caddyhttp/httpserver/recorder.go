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

package httpserver

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"time"
)

// ResponseRecorder is a type of http.ResponseWriter that captures
// the status code written to it and also the size of the body
// written in the response. A status code does not have
// to be written, however, in which case 200 must be assumed.
// It is best to have the constructor initialize this type
// with that default status code.
//
// Setting the Replacer field allows middlewares to type-assert
// the http.ResponseWriter to ResponseRecorder and set their own
// placeholder values for logging utilities to use.
//
// Beware when accessing the Replacer value; it may be nil!
type ResponseRecorder struct {
	*ResponseWriterWrapper
	Replacer Replacer
	status   int
	size     int
	start    time.Time
}

// NewResponseRecorder makes and returns a new ResponseRecorder.
// Because a status is not set unless WriteHeader is called
// explicitly, this constructor initializes with a status code
// of 200 to cover the default case.
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: w},
		status:                http.StatusOK,
		start:                 time.Now(),
	}
}

// WriteHeader records the status code and calls the
// underlying ResponseWriter's WriteHeader method.
func (r *ResponseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriterWrapper.WriteHeader(status)
}

// Write is a wrapper that records the size of the body
// that gets written.
func (r *ResponseRecorder) Write(buf []byte) (int, error) {
	n, err := r.ResponseWriterWrapper.Write(buf)
	if err == nil {
		r.size += n
	}
	return n, err
}

// Size returns the size of the recorded response body.
func (r *ResponseRecorder) Size() int {
	return r.size
}

// Status returns the recorded response status code.
func (r *ResponseRecorder) Status() int {
	return r.status
}

// ResponseBuffer is a type that conditionally buffers the
// response in memory. It implements http.ResponseWriter so
// that it can stream the response if it is not buffering.
// Whether it buffers is decided by a func passed into the
// constructor, NewResponseBuffer.
//
// This type implements http.ResponseWriter, so you can pass
// this to the Next() middleware in the chain and record its
// response. However, since the entire response body will be
// buffered in memory, only use this when explicitly configured
// and required for some specific reason. For example, the
// text/template package only parses templates out of []byte
// and not io.Reader, so the templates directive uses this
// type to obtain the entire template text, but only on certain
// requests that match the right Content-Type, etc.
//
// ResponseBuffer also implements io.ReaderFrom for performance
// reasons. The standard lib's http.response type (unexported)
// uses io.Copy to write the body. io.Copy makes an allocation
// if the destination does not have a ReadFrom method (or if
// the source does not have a WriteTo method, but that's
// irrelevant here). Our ReadFrom is smart: if buffering, it
// calls the buffer's ReadFrom, which makes no allocs because
// it is already a buffer! If we're streaming the response
// instead, ReadFrom uses io.CopyBuffer with a pooled buffer
// that is managed within this package.
type ResponseBuffer struct {
	*ResponseWriterWrapper
	Buffer       *bytes.Buffer
	header       http.Header
	status       int
	shouldBuffer func(status int, header http.Header) bool
	stream       bool
	rw           http.ResponseWriter
	wroteHeader  bool
}

// NewResponseBuffer returns a new ResponseBuffer that will
// use buf to store the full body of the response if shouldBuffer
// returns true. If shouldBuffer returns false, then the response
// body will be streamed directly to rw.
//
// shouldBuffer will be passed the status code and header fields of
// the response. With that information, the function should decide
// whether to buffer the response in memory. For example: the templates
// directive uses this to determine whether the response is the
// right Content-Type (according to user config) for a template.
//
// For performance, the buf you pass in should probably be obtained
// from a sync.Pool in order to reuse allocated space.
func NewResponseBuffer(buf *bytes.Buffer, rw http.ResponseWriter,
	shouldBuffer func(status int, header http.Header) bool) *ResponseBuffer {
	rb := &ResponseBuffer{
		Buffer:       buf,
		header:       make(http.Header),
		status:       http.StatusOK, // default status code
		shouldBuffer: shouldBuffer,
		rw:           rw,
	}
	rb.ResponseWriterWrapper = &ResponseWriterWrapper{ResponseWriter: rw}
	return rb
}

// Header returns the response header map.
func (rb *ResponseBuffer) Header() http.Header {
	return rb.header
}

// WriteHeader calls shouldBuffer to decide whether the
// upcoming body should be buffered, and then writes
// the header to the response.
func (rb *ResponseBuffer) WriteHeader(status int) {
	if rb.wroteHeader {
		return
	}
	rb.wroteHeader = true

	rb.status = status
	rb.stream = !rb.shouldBuffer(status, rb.header)
	if rb.stream {
		rb.CopyHeader()
		rb.ResponseWriterWrapper.WriteHeader(status)
	}
}

// Write writes buf to rb.Buffer if buffering, otherwise
// to the ResponseWriter directly if streaming.
func (rb *ResponseBuffer) Write(buf []byte) (int, error) {
	if !rb.wroteHeader {
		rb.WriteHeader(http.StatusOK)
	}

	if rb.stream {
		return rb.ResponseWriterWrapper.Write(buf)
	}
	return rb.Buffer.Write(buf)
}

// Buffered returns whether rb has decided to buffer the response.
func (rb *ResponseBuffer) Buffered() bool {
	return !rb.stream
}

// CopyHeader copies the buffered header in rb to the ResponseWriter,
// but it does not write the header out.
func (rb *ResponseBuffer) CopyHeader() {
	for field, val := range rb.header {
		rb.ResponseWriterWrapper.Header()[field] = val
	}
}

// ReadFrom avoids allocations when writing to the buffer (if buffering),
// and reduces allocations when writing to the ResponseWriter directly
// (if streaming).
//
// In local testing with the templates directive, req/sec were improved
// from ~8,200 to ~9,600 on templated files by ensuring that this type
// implements io.ReaderFrom.
func (rb *ResponseBuffer) ReadFrom(src io.Reader) (int64, error) {
	if !rb.wroteHeader {
		rb.WriteHeader(http.StatusOK)
	}

	if rb.stream {
		// first see if we can avoid any allocations at all
		if wt, ok := src.(io.WriterTo); ok {
			return wt.WriteTo(rb.ResponseWriterWrapper)
		}
		// if not, use a pooled copy buffer to reduce allocs
		// (this improved req/sec from ~25,300 to ~27,000 on
		// static files served directly with the fileserver,
		// but results fluctuated a little on each run).
		// a note of caution:
		// https://go-review.googlesource.com/c/22134#message-ff351762308fe05f6b72a487d6842e3988916486
		buf := respBufPool.Get().([]byte)
		n, err := io.CopyBuffer(rb.ResponseWriterWrapper, src, buf)
		respBufPool.Put(buf) // defer'ing this slowed down benchmarks a smidgin, I think
		return n, err
	}
	return rb.Buffer.ReadFrom(src)
}

// StatusCodeWriter returns an http.ResponseWriter that always
// writes the status code stored in rb from when a response
// was buffered to it.
func (rb *ResponseBuffer) StatusCodeWriter(w http.ResponseWriter) http.ResponseWriter {
	return forcedStatusCodeWriter{w, rb}
}

// forcedStatusCodeWriter is used to force a status code when
// writing the header. It uses the status code saved on rb.
// This is useful if passing a http.ResponseWriter into
// http.ServeContent because ServeContent hard-codes 2xx status
// codes. If we buffered the response, we force that status code
// instead.
type forcedStatusCodeWriter struct {
	http.ResponseWriter
	rb *ResponseBuffer
}

func (fscw forcedStatusCodeWriter) WriteHeader(int) {
	fscw.ResponseWriter.WriteHeader(fscw.rb.status)
}

// respBufPool is used for io.CopyBuffer when ResponseBuffer
// is configured to stream a response.
var respBufPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

// Interface guards
var (
	_ HTTPInterfaces = (*ResponseRecorder)(nil)
	_ HTTPInterfaces = (*ResponseBuffer)(nil)
	_ io.ReaderFrom  = (*ResponseBuffer)(nil)
)
