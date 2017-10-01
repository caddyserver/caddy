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
	"bufio"
	"net"
	"net/http"
)

// ResponseWriterWrapper wrappers underlying ResponseWriter
// and inherits its Hijacker/Pusher/CloseNotifier/Flusher as well.
type ResponseWriterWrapper struct {
	http.ResponseWriter
}

// Hijack implements http.Hijacker. It simply wraps the underlying
// ResponseWriter's Hijack method if there is one, or returns an error.
func (rww *ResponseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rww.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, NonHijackerError{Underlying: rww.ResponseWriter}
}

// Flush implements http.Flusher. It simply wraps the underlying
// ResponseWriter's Flush method if there is one, or panics.
func (rww *ResponseWriterWrapper) Flush() {
	if f, ok := rww.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	} else {
		panic(NonFlusherError{Underlying: rww.ResponseWriter})
	}
}

// CloseNotify implements http.CloseNotifier.
// It just inherits the underlying ResponseWriter's CloseNotify method.
// It panics if the underlying ResponseWriter is not a CloseNotifier.
func (rww *ResponseWriterWrapper) CloseNotify() <-chan bool {
	if cn, ok := rww.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	panic(NonCloseNotifierError{Underlying: rww.ResponseWriter})
}

// Push implements http.Pusher.
// It just inherits the underlying ResponseWriter's Push method.
// It panics if the underlying ResponseWriter is not a Pusher.
func (rww *ResponseWriterWrapper) Push(target string, opts *http.PushOptions) error {
	if pusher, hasPusher := rww.ResponseWriter.(http.Pusher); hasPusher {
		return pusher.Push(target, opts)
	}

	return NonPusherError{Underlying: rww.ResponseWriter}
}

// HTTPInterfaces mix all the interfaces that middleware ResponseWriters need to support.
type HTTPInterfaces interface {
	http.ResponseWriter
	http.Pusher
	http.Flusher
	http.CloseNotifier
	http.Hijacker
}

// Interface guards
var _ HTTPInterfaces = (*ResponseWriterWrapper)(nil)
