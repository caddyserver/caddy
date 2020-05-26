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
	"io"
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
	statusCode   int
	buf          *bytes.Buffer
	shouldBuffer ShouldBufferFunc
	size         int
	wroteHeader  bool
	stream       bool
}

// NewResponseRecorder returns a new ResponseRecorder that can be
// used instead of a standard http.ResponseWriter. The recorder is
// useful for middlewares which need to buffer a response and
// potentially process its entire body before actually writing the
// response to the underlying writer. Of course, buffering the entire
// body has a memory overhead, but sometimes there is no way to avoid
// buffering the whole response, hence the existence of this type.
// Still, if at all practical, handlers should strive to stream
// responses by wrapping Write and WriteHeader methods instead of
// buffering whole response bodies.
//
// Buffering is actually optional. The shouldBuffer function will
// be called just before the headers are written. If it returns
// true, the headers and body will be buffered by this recorder
// and not written to the underlying writer; if false, the headers
// will be written immediately and the body will be streamed out
// directly to the underlying writer. If shouldBuffer is nil,
// the response will never be buffered and will always be streamed
// directly to the writer.
//
// You can know if shouldBuffer returned true by calling Buffered().
//
// The provided buffer buf should be obtained from a pool for best
// performance (see the sync.Pool type).
//
// Proper usage of a recorder looks like this:
//
//     rec := caddyhttp.NewResponseRecorder(w, buf, shouldBuffer)
//     err := next.ServeHTTP(rec, req)
//     if err != nil {
//         return err
//     }
//     if !rec.Buffered() {
//         return nil
//     }
//     // process the buffered response here
//
// The header map is not buffered; i.e. the ResponseRecorder's Header()
// method returns the same header map of the underlying ResponseWriter.
// This is a crucial design decision to allow HTTP trailers to be
// flushed properly (https://github.com/caddyserver/caddy/issues/3236).
//
// Once you are ready to write the response, there are two ways you can
// do it. The easier way is to have the recorder do it:
//
//     rec.WriteResponse()
//
// This writes the recorded response headers as well as the buffered body.
// Or, you may wish to do it yourself, especially if you manipulated the
// buffered body. First you will need to write the headers with the
// recorded status code, then write the body (this example writes the
// recorder's body buffer, but you might have your own body to write
// instead):
//
//     w.WriteHeader(rec.Status())
//     io.Copy(w, rec.Buffer())
//
func NewResponseRecorder(w http.ResponseWriter, buf *bytes.Buffer, shouldBuffer ShouldBufferFunc) ResponseRecorder {
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
		rr.stream = !rr.shouldBuffer(rr.statusCode, rr.ResponseWriterWrapper.Header())
	}

	// if not buffered, immediately write header
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

func (rr *responseRecorder) WriteResponse() error {
	if rr.stream {
		return nil
	}
	if rr.statusCode == 0 {
		// could happen if no handlers actually wrote anything,
		// and this prevents a panic; status must be > 0
		rr.statusCode = http.StatusOK
	}
	rr.ResponseWriterWrapper.WriteHeader(rr.statusCode)
	_, err := io.Copy(rr.ResponseWriterWrapper, rr.buf)
	return err
}

// ResponseRecorder is a http.ResponseWriter that records
// responses instead of writing them to the client. See
// docs for NewResponseRecorder for proper usage.
type ResponseRecorder interface {
	HTTPInterfaces
	Status() int
	Buffer() *bytes.Buffer
	Buffered() bool
	Size() int
	WriteResponse() error
}

// ShouldBufferFunc is a function that returns true if the
// response should be buffered, given the pending HTTP status
// code and response headers.
type ShouldBufferFunc func(status int, header http.Header) bool

// Interface guards
var (
	_ HTTPInterfaces   = (*ResponseWriterWrapper)(nil)
	_ ResponseRecorder = (*responseRecorder)(nil)
)
