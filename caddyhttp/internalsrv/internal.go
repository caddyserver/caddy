// Package internalsrv provides a simple middleware that (a) prevents access
// to internal locations and (b) allows to return files from internal location
// by setting a special header, e.g. in a proxy response.
//
// The package is named internalsrv so as not to conflict with Go tooling
// convention which treats folders called "internal" differently.
package internalsrv

import (
	"bufio"
	"net"
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Internal middleware protects internal locations from external requests -
// but allows access from the inside by using a special HTTP header.
type Internal struct {
	Next  httpserver.Handler
	Paths []string
}

const (
	redirectHeader        string = "X-Accel-Redirect"
	contentLengthHeader   string = "Content-Length"
	contentEncodingHeader string = "Content-Encoding"
	maxRedirectCount      int    = 10
)

func isInternalRedirect(w http.ResponseWriter) bool {
	return w.Header().Get(redirectHeader) != ""
}

// ServeHTTP implements the httpserver.Handler interface.
func (i Internal) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	// Internal location requested? -> Not found.
	for _, prefix := range i.Paths {
		if httpserver.Path(r.URL.Path).Matches(prefix) {
			return http.StatusNotFound, nil
		}
	}

	// Use internal response writer to ignore responses that will be
	// redirected to internal locations
	iw := internalResponseWriter{ResponseWriter: w}
	status, err := i.Next.ServeHTTP(iw, r)

	for c := 0; c < maxRedirectCount && isInternalRedirect(iw); c++ {
		// Redirect - adapt request URL path and send it again
		// "down the chain"
		r.URL.Path = iw.Header().Get(redirectHeader)
		iw.ClearHeader()

		status, err = i.Next.ServeHTTP(iw, r)
	}

	if isInternalRedirect(iw) {
		// Too many redirect cycles
		iw.ClearHeader()
		return http.StatusInternalServerError, nil
	}

	return status, err
}

// internalResponseWriter wraps the underlying http.ResponseWriter and ignores
// calls to Write and WriteHeader if the response should be redirected to an
// internal location.
type internalResponseWriter struct {
	http.ResponseWriter
}

// ClearHeader removes script headers that would interfere with follow up
// redirect requests.
func (w internalResponseWriter) ClearHeader() {
	w.Header().Del(redirectHeader)
	w.Header().Del(contentLengthHeader)
	w.Header().Del(contentEncodingHeader)
}

// WriteHeader ignores the call if the response should be redirected to an
// internal location.
func (w internalResponseWriter) WriteHeader(code int) {
	if !isInternalRedirect(w) {
		w.ResponseWriter.WriteHeader(code)
	}
}

// Write ignores the call if the response should be redirected to an internal
// location.
func (w internalResponseWriter) Write(b []byte) (int, error) {
	if isInternalRedirect(w) {
		return 0, nil
	}
	return w.ResponseWriter.Write(b)
}

// Hijack implements http.Hijacker. It simply wraps the underlying
// ResponseWriter's Hijack method if there is one, or returns an error.
func (w internalResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, httpserver.NonHijackerError{Underlying: w.ResponseWriter}
}

// Flush implements http.Flusher. It simply wraps the underlying
// ResponseWriter's Flush method if there is one, or panics.
func (w internalResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	} else {
		panic(httpserver.NonFlusherError{Underlying: w.ResponseWriter})
	}
}

// CloseNotify implements http.CloseNotifier.
// It just inherits the underlying ResponseWriter's CloseNotify method.
// It panics if the underlying ResponseWriter is not a CloseNotifier.
func (w internalResponseWriter) CloseNotify() <-chan bool {
	if cn, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	panic(httpserver.NonCloseNotifierError{Underlying: w.ResponseWriter})
}

// Push implements http.Pusher.
// It just inherits the underlying ResponseWriter's Push method.
// It panics if the underlying ResponseWriter is not a Pusher.
func (w internalResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, hasPusher := w.ResponseWriter.(http.Pusher); hasPusher {
		return pusher.Push(target, opts)
	}

	return httpserver.NonPusherError{Underlying: w.ResponseWriter}
}

// Interface guards
var (
	_ http.Pusher        = internalResponseWriter{}
	_ http.Flusher       = internalResponseWriter{}
	_ http.CloseNotifier = internalResponseWriter{}
	_ http.Hijacker      = internalResponseWriter{}
)
