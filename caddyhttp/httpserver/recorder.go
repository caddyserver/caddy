package httpserver

import (
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
	*ResponseWriterWrapper
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

// Size is a Getter to size property
func (r *ResponseRecorder) Size() int {
	return r.size
}

// Status is a Getter to status property
func (r *ResponseRecorder) Status() int {
	return r.status
}

// Interface guards
var _ HTTPInterfaces = (*ResponseRecorder)(nil)
