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

package limits

import (
	"io"
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Limit is a middleware to control request body size
type Limit struct {
	Next       httpserver.Handler
	BodyLimits []httpserver.PathLimit
}

func (l Limit) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if r.Body == nil {
		return l.Next.ServeHTTP(w, r)
	}

	// apply the path-based request body size limit.
	for _, bl := range l.BodyLimits {
		if httpserver.Path(r.URL.Path).Matches(bl.Path) {
			r.Body = MaxBytesReader(w, r.Body, bl.Limit)
			break
		}
	}

	return l.Next.ServeHTTP(w, r)
}

// MaxBytesReader and its associated methods are borrowed from the
// Go Standard library (comments intact). The only difference is that
// it returns a ErrMaxBytesExceeded error instead of a generic error message
// when the request body has exceeded the requested limit
func MaxBytesReader(w http.ResponseWriter, r io.ReadCloser, n int64) io.ReadCloser {
	return &maxBytesReader{w: w, r: r, n: n}
}

type maxBytesReader struct {
	w   http.ResponseWriter
	r   io.ReadCloser // underlying reader
	n   int64         // max bytes remaining
	err error         // sticky error
}

func (l *maxBytesReader) Read(p []byte) (n int, err error) {
	if l.err != nil {
		return 0, l.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// If they asked for a 32KB byte read but only 5 bytes are
	// remaining, no need to read 32KB. 6 bytes will answer the
	// question of the whether we hit the limit or go past it.
	if int64(len(p)) > l.n+1 {
		p = p[:l.n+1]
	}
	n, err = l.r.Read(p)

	if int64(n) <= l.n {
		l.n -= int64(n)
		l.err = err
		return n, err
	}

	n = int(l.n)
	l.n = 0

	// The server code and client code both use
	// maxBytesReader. This "requestTooLarge" check is
	// only used by the server code. To prevent binaries
	// which only using the HTTP Client code (such as
	// cmd/go) from also linking in the HTTP server, don't
	// use a static type assertion to the server
	// "*response" type. Check this interface instead:
	type requestTooLarger interface {
		requestTooLarge()
	}
	if res, ok := l.w.(requestTooLarger); ok {
		res.requestTooLarge()
	}
	l.err = httpserver.ErrMaxBytesExceeded
	return n, l.err
}

func (l *maxBytesReader) Close() error {
	return l.r.Close()
}
