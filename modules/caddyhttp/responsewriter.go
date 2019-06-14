package caddyhttp

import (
	"bufio"
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

// Interface guards
var _ HTTPInterfaces = (*ResponseWriterWrapper)(nil)
