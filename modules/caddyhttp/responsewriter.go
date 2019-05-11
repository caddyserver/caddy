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
// ResponseWriter's Hijack method if there is one, or returns an error.
func (rww *ResponseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rww.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("not a hijacker")
}

// Flush implements http.Flusher. It simply calls the underlying
// ResponseWriter's Flush method if there is one, or panics.
func (rww *ResponseWriterWrapper) Flush() {
	if f, ok := rww.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	} else {
		panic("not a flusher")
	}
}

// Push implements http.Pusher. It simply calls the underlying
// ResponseWriter's Push method if there is one, or returns an error.
func (rww *ResponseWriterWrapper) Push(target string, opts *http.PushOptions) error {
	if pusher, hasPusher := rww.ResponseWriter.(http.Pusher); hasPusher {
		return pusher.Push(target, opts)
	}
	return fmt.Errorf("not a pusher")
}

// HTTPInterfaces mix all the interfaces that middleware ResponseWriters need to support.
type HTTPInterfaces interface {
	http.ResponseWriter
	http.Pusher
	http.Flusher
	http.Hijacker
}

// Interface guards
var _ HTTPInterfaces = (*ResponseWriterWrapper)(nil)
