package httpserver

import (
	"bufio"
	"errors"
	"net"
	"net/http"
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
	http.ResponseWriter
	Replacer Replacer
	status   int
	size     int
	start    time.Time
}

// NewResponseRecorder makes and returns a new responseRecorder,
// which captures the HTTP Status code from the ResponseWriter
// and also the length of the response body written through it.
// Because a status is not set unless WriteHeader is called
// explicitly, this constructor initializes with a status code
// of 200 to cover the default case.
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		status:         http.StatusOK,
		start:          time.Now(),
	}
}

// WriteHeader records the status code and calls the
// underlying ResponseWriter's WriteHeader method.
func (r *ResponseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Write is a wrapper that records the size of the body
// that gets written.
func (r *ResponseRecorder) Write(buf []byte) (int, error) {
	n, err := r.ResponseWriter.Write(buf)
	if err == nil {
		r.size += n
	}
	return n, err
}

// Size is a Getter to size property
func (r *ResponseRecorder) Size() int {
	return r.size
}

// Status is a Getter to status property
func (r *ResponseRecorder) Status() int {
	return r.status
}

// Hijack implements http.Hijacker. It simply wraps the underlying
// ResponseWriter's Hijack method if there is one, or returns an error.
func (r *ResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, NonHijackerError{Underlying: r.ResponseWriter}
}

// Flush implements http.Flusher. It simply wraps the underlying
// ResponseWriter's Flush method if there is one, or does nothing.
func (r *ResponseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	} else {
		panic(NonFlusherError{Underlying: r.ResponseWriter}) // should be recovered at the beginning of middleware stack
	}
}

// CloseNotify implements http.CloseNotifier.
// It just inherits the underlying ResponseWriter's CloseNotify method.
func (r *ResponseRecorder) CloseNotify() <-chan bool {
	if cn, ok := r.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	panic(NonCloseNotifierError{Underlying: r.ResponseWriter})
}

// Push resource to client
func (r *ResponseRecorder) Push(target string, opts *http.PushOptions) error {
	if pusher, hasPusher := r.ResponseWriter.(http.Pusher); hasPusher {
		return pusher.Push(target, opts)
	}

	return errors.New("push is unavailable (probably chained http.ResponseWriter does not implement http.Pusher)")
}

// Interface guards
var _ http.Pusher = (*ResponseRecorder)(nil)
var _ http.Flusher = (*ResponseRecorder)(nil)
var _ http.CloseNotifier = (*ResponseRecorder)(nil)
var _ http.Hijacker = (*ResponseRecorder)(nil)
