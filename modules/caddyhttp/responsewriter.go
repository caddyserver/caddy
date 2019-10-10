// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddyhttp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
)

// ResponseWriterWrapper wraps an underlying ResponseWriter and
// promotes its Pusher/Flusher/Hijacker methods as well. To use
// this type, embed a pointer to it within your own struct type
// that implements the http.ResponseWriter interface, then call
// methods on the embedded value. You can make sure your type
// wraps correctly by asserting that it implements the
// HTTPInterfaces interface.
type ResponseWriterWrapper struct {
	http.ResponseWriter
}

// Hijack implements http.Hijacker. It simply calls the underlying
// ResponseWriter's Hijack method if there is one, or returns
// ErrNotImplemented otherwise.
func (rww *ResponseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rww.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, ErrNotImplemented
}

// Flush implements http.Flusher. It simply calls the underlying
// ResponseWriter's Flush method if there is one.
func (rww *ResponseWriterWrapper) Flush() {
	if f, ok := rww.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Push implements http.Pusher. It simply calls the underlying
// ResponseWriter's Push method if there is one, or returns
// ErrNotImplemented otherwise.
func (rww *ResponseWriterWrapper) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := rww.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return ErrNotImplemented
}

// HTTPInterfaces mix all the interfaces that middleware ResponseWriters need to support.
type HTTPInterfaces interface {
	http.ResponseWriter
	http.Pusher
	http.Flusher
	http.Hijacker
}

// ErrNotImplemented is returned when an underlying
// ResponseWriter does not implement the required method.
var ErrNotImplemented = fmt.Errorf("method not implemented")

type responseRecorder struct {
	*ResponseWriterWrapper
	wroteHeader  bool
	statusCode   int
	buf          *bytes.Buffer
	shouldBuffer func(status int) bool
	stream       bool
	size         int
}

// NewResponseRecorder returns a new ResponseRecorder that can be
// used instead of a real http.ResponseWriter. The recorder is useful
// for middlewares which need to buffer a responder's response and
// process it in its entirety before actually allowing the response to
// be written. Of course, this has a performance overhead, but
// sometimes there is no way to avoid buffering the whole response.
// Still, if at all practical, middlewares should strive to stream
// responses by wrapping Write and WriteHeader methods instead of
// buffering whole response bodies.
//
// Recorders optionally buffer the response. When the headers are
// to be written, shouldBuffer will be called with the status
// code that is being written. The rest of the headers can be read
// from w.Header(). If shouldBuffer returns true, the response
// will be buffered. You can know the response was buffered if
// the Buffered() method returns true. If the response was not
// buffered, Buffered() will return false and that means the
// response bypassed the recorder and was written directly to the
// underlying writer. If shouldBuffer is nil, the response will
// never be buffered (it will always be streamed directly), and
// buf can also safely be nil.
//
// Before calling this function in a middleware handler, make a
// new buffer or obtain one from a pool (use the sync.Pool) type.
// Using a pool is generally recommended for performance gains;
// do profiling to ensure this is the case. If using a pool, be
// sure to reset the buffer before using it.
//
// The returned recorder can be used in place of w when calling
// the next handler in the chain. When that handler returns, you
// can read the status code from the recorder's Status() method.
// The response body fills buf if it was buffered, and the headers
// are available via w.Header().
func NewResponseRecorder(w http.ResponseWriter, buf *bytes.Buffer, shouldBuffer func(status int) bool) ResponseRecorder {
	return &responseRecorder{
		ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: w},
		buf:                   buf,
		shouldBuffer:          shouldBuffer,
	}
}

func (rr *responseRecorder) WriteHeader(statusCode int) {
	if rr.wroteHeader {
		return
	}
	rr.statusCode = statusCode
	rr.wroteHeader = true

	// decide whether we should buffer the response
	if rr.shouldBuffer == nil {
		rr.stream = true
	} else {
		rr.stream = !rr.shouldBuffer(rr.statusCode)
	}
	if rr.stream {
		rr.ResponseWriterWrapper.WriteHeader(rr.statusCode)
	}
}

func (rr *responseRecorder) Write(data []byte) (int, error) {
	rr.WriteHeader(http.StatusOK)
	var n int
	var err error
	if rr.stream {
		n, err = rr.ResponseWriterWrapper.Write(data)
	} else {
		n, err = rr.buf.Write(data)
	}
	if err == nil {
		rr.size += n
	}
	return n, err
}

// Status returns the status code that was written, if any.
func (rr *responseRecorder) Status() int {
	return rr.statusCode
}

// Size returns the number of bytes written,
// not including the response headers.
func (rr *responseRecorder) Size() int {
	return rr.size
}

// Buffer returns the body buffer that rr was created with.
// You should still have your original pointer, though.
func (rr *responseRecorder) Buffer() *bytes.Buffer {
	return rr.buf
}

// Buffered returns whether rr has decided to buffer the response.
func (rr *responseRecorder) Buffered() bool {
	return !rr.stream
}

// ResponseRecorder is a http.ResponseWriter that records
// responses instead of writing them to the client.
type ResponseRecorder interface {
	HTTPInterfaces
	Status() int
	Buffer() *bytes.Buffer
	Buffered() bool
	Size() int
}

// Interface guards
var (
	_ HTTPInterfaces   = (*ResponseWriterWrapper)(nil)
	_ ResponseRecorder = (*responseRecorder)(nil)
)
