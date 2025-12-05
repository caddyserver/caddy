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
// promotes its Pusher method as well. To use this type, embed
// a pointer to it within your own struct type that implements
// the http.ResponseWriter interface, then call methods on the
// embedded value.
type ResponseWriterWrapper struct {
	http.ResponseWriter
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

// ReadFrom implements io.ReaderFrom. It retries to use io.ReaderFrom if available,
// then fallback to io.Copy.
// see: https://github.com/caddyserver/caddy/issues/6546
func (rww *ResponseWriterWrapper) ReadFrom(r io.Reader) (n int64, err error) {
	if rf, ok := rww.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(rww.ResponseWriter, r)
}

// Unwrap returns the underlying ResponseWriter, necessary for
// http.ResponseController to work correctly.
func (rww *ResponseWriterWrapper) Unwrap() http.ResponseWriter {
	return rww.ResponseWriter
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

	readSize *int
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
//	rec := caddyhttp.NewResponseRecorder(w, buf, shouldBuffer)
//	err := next.ServeHTTP(rec, req)
//	if err != nil {
//	    return err
//	}
//	if !rec.Buffered() {
//	    return nil
//	}
//	// process the buffered response here
//
// The header map is not buffered; i.e. the ResponseRecorder's Header()
// method returns the same header map of the underlying ResponseWriter.
// This is a crucial design decision to allow HTTP trailers to be
// flushed properly (https://github.com/caddyserver/caddy/issues/3236).
//
// Once you are ready to write the response, there are two ways you can
// do it. The easier way is to have the recorder do it:
//
//	rec.WriteResponse()
//
// This writes the recorded response headers as well as the buffered body.
// Or, you may wish to do it yourself, especially if you manipulated the
// buffered body. First you will need to write the headers with the
// recorded status code, then write the body (this example writes the
// recorder's body buffer, but you might have your own body to write
// instead):
//
//	w.WriteHeader(rec.Status())
//	io.Copy(w, rec.Buffer())
//
// As a special case, 1xx responses are not buffered nor recorded
// because they are not the final response; they are passed through
// directly to the underlying ResponseWriter.
func NewResponseRecorder(w http.ResponseWriter, buf *bytes.Buffer, shouldBuffer ShouldBufferFunc) ResponseRecorder {
	return &responseRecorder{
		ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: w},
		buf:                   buf,
		shouldBuffer:          shouldBuffer,
	}
}

// WriteHeader writes the headers with statusCode to the wrapped
// ResponseWriter unless the response is to be buffered instead.
// 1xx responses are never buffered.
func (rr *responseRecorder) WriteHeader(statusCode int) {
	if rr.wroteHeader {
		return
	}

	// save statusCode always, in case HTTP middleware upgrades websocket
	// connections by manually setting headers and writing status 101
	rr.statusCode = statusCode

	// decide whether we should buffer the response
	if rr.shouldBuffer == nil {
		rr.stream = true
	} else {
		rr.stream = !rr.shouldBuffer(rr.statusCode, rr.ResponseWriterWrapper.Header())
	}

	// 1xx responses aren't final; just informational
	if statusCode < 100 || statusCode > 199 {
		rr.wroteHeader = true
	}

	// if informational or not buffered, immediately write header
	if rr.stream || (100 <= statusCode && statusCode <= 199) {
		rr.ResponseWriterWrapper.WriteHeader(statusCode)
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

	rr.size += n
	return n, err
}

func (rr *responseRecorder) ReadFrom(r io.Reader) (int64, error) {
	rr.WriteHeader(http.StatusOK)
	var n int64
	var err error
	if rr.stream {
		n, err = rr.ResponseWriterWrapper.ReadFrom(r)
	} else {
		n, err = rr.buf.ReadFrom(r)
	}

	rr.size += int(n)
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
	if rr.statusCode == 0 {
		// could happen if no handlers actually wrote anything,
		// and this prevents a panic; status must be > 0
		rr.WriteHeader(http.StatusOK)
	}
	if rr.stream {
		return nil
	}
	rr.ResponseWriterWrapper.WriteHeader(rr.statusCode)
	_, err := io.Copy(rr.ResponseWriterWrapper, rr.buf)
	return err
}

// FlushError will suppress actual flushing if the response is buffered. See:
// https://github.com/caddyserver/caddy/issues/6144
func (rr *responseRecorder) FlushError() error {
	if rr.stream {
		//nolint:bodyclose
		return http.NewResponseController(rr.ResponseWriterWrapper).Flush()
	}
	return nil
}

// Private interface so it can only be used in this package
// #TODO: maybe export it later
func (rr *responseRecorder) setReadSize(size *int) {
	rr.readSize = size
}

func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	//nolint:bodyclose
	conn, brw, err := http.NewResponseController(rr.ResponseWriterWrapper).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// Per http documentation, returned bufio.Writer is empty, but bufio.Read maybe not
	conn = &hijackedConn{conn, rr}
	brw.Writer.Reset(conn)

	buffered := brw.Reader.Buffered()
	if buffered != 0 {
		conn.(*hijackedConn).updateReadSize(buffered)
		data, _ := brw.Peek(buffered)
		brw.Reader.Reset(io.MultiReader(bytes.NewReader(data), conn))
		// peek to make buffered data appear, as Reset will make it 0
		_, _ = brw.Peek(buffered)
	} else {
		brw.Reader.Reset(conn)
	}
	return conn, brw, nil
}

// used to track the size of hijacked response writers
type hijackedConn struct {
	net.Conn
	rr *responseRecorder
}

func (hc *hijackedConn) updateReadSize(n int) {
	if hc.rr.readSize != nil {
		*hc.rr.readSize += n
	}
}

func (hc *hijackedConn) Read(p []byte) (int, error) {
	n, err := hc.Conn.Read(p)
	hc.updateReadSize(n)
	return n, err
}

func (hc *hijackedConn) WriteTo(w io.Writer) (int64, error) {
	n, err := io.Copy(w, hc.Conn)
	hc.updateReadSize(int(n))
	return n, err
}

func (hc *hijackedConn) Write(p []byte) (int, error) {
	n, err := hc.Conn.Write(p)
	hc.rr.size += n
	return n, err
}

func (hc *hijackedConn) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(hc.Conn, r)
	hc.rr.size += int(n)
	return n, err
}

// ResponseRecorder is a http.ResponseWriter that records
// responses instead of writing them to the client. See
// docs for NewResponseRecorder for proper usage.
type ResponseRecorder interface {
	http.ResponseWriter
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
	_ http.ResponseWriter = (*ResponseWriterWrapper)(nil)
	_ ResponseRecorder    = (*responseRecorder)(nil)

	// Implementing ReaderFrom can be such a significant
	// optimization that it should probably be required!
	// see PR #5022 (25%-50% speedup)
	_ io.ReaderFrom = (*ResponseWriterWrapper)(nil)
	_ io.ReaderFrom = (*responseRecorder)(nil)
	_ io.ReaderFrom = (*hijackedConn)(nil)

	_ io.WriterTo = (*hijackedConn)(nil)
)
