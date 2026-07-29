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

package requestbody

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(RequestBody{})
}

// RequestBody is a middleware for manipulating the request body.
type RequestBody struct {
	// The maximum number of bytes to allow reading from the body by a later handler.
	// If more bytes are read, an error with HTTP status 413 is returned.
	MaxSize int64 `json:"max_size,omitempty"`

	// How long to allow a read from the request body to stall before
	// aborting the connection, reset on every successful read (like the
	// server-wide read_idle_timeout, but scoped to routes matching this
	// handler). If zero, no idle timeout is applied here.
	// EXPERIMENTAL. Subject to change/removal.
	ReadTimeout time.Duration `json:"read_timeout,omitempty"`

	// ReadMinRate requires the client to sustain at least this many
	// bytes/second, averaged from the start of the read, or the
	// connection is aborted (Apache mod_reqtimeout's MinRate). Only
	// takes effect if ReadTimeout is also set.
	// EXPERIMENTAL. Subject to change/removal.
	ReadMinRate int64 `json:"read_min_rate,omitempty"`

	// How long to allow a write to the client to stall before aborting
	// the connection, reset on every successful write (like the
	// server-wide write_idle_timeout, but scoped to routes matching this
	// handler). If zero, no idle timeout is applied here.
	// EXPERIMENTAL. Subject to change/removal.
	WriteTimeout time.Duration `json:"write_timeout,omitempty"`

	// WriteMinRate is like ReadMinRate, but for writes to the client.
	// Only takes effect if WriteTimeout is also set.
	// EXPERIMENTAL. Subject to change/removal.
	WriteMinRate int64 `json:"write_min_rate,omitempty"`

	// MaxWriteChunk bounds how many bytes a single underlying write
	// operation is allowed to cover, so WriteTimeout/WriteMinRate can
	// actually apply between chunks of a large response instead of
	// being bounded by one deadline for the whole thing. If zero,
	// caddyhttp.DefaultMaxWriteChunk is used.
	// EXPERIMENTAL. Subject to change/removal.
	MaxWriteChunk int `json:"max_write_chunk,omitempty"`

	// This field permit to replace body on the fly
	// EXPERIMENTAL. Subject to change/removal.
	Set string `json:"set,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (RequestBody) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.request_body",
		New: func() caddy.Module { return new(RequestBody) },
	}
}

func (rb *RequestBody) Provision(ctx caddy.Context) error {
	rb.logger = ctx.Logger()
	return nil
}

func (rb RequestBody) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if rb.Set != "" {
		if r.Body != nil {
			err := r.Body.Close()
			if err != nil {
				return err
			}
		}
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		replacedBody := repl.ReplaceAll(rb.Set, "")
		r.Body = io.NopCloser(strings.NewReader(replacedBody))
		r.ContentLength = int64(len(replacedBody))
	}
	if r.Body == nil {
		return next.ServeHTTP(w, r)
	}
	if rb.MaxSize > 0 {
		r.Body = errorWrapper{http.MaxBytesReader(w, r.Body, rb.MaxSize)}
	}
	if rb.ReadTimeout > 0 || rb.WriteTimeout > 0 {
		//nolint:bodyclose
		rc := http.NewResponseController(w)
		start := time.Now()
		if rb.ReadTimeout > 0 {
			r.Body = &caddyhttp.IdleTimeoutReader{
				ReadCloser: r.Body,
				Ctrl:       rc,
				Deadline: caddyhttp.IdleDeadline{
					Start:   start,
					Timeout: rb.ReadTimeout,
					MinRate: rb.ReadMinRate,
				},
				Logger: rb.logger,
			}
		}
		if rb.WriteTimeout > 0 {
			w = &caddyhttp.IdleTimeoutWriter{
				ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
				Ctrl:                  rc,
				Deadline: caddyhttp.IdleDeadline{
					Start:   start,
					Timeout: rb.WriteTimeout,
					MinRate: rb.WriteMinRate,
				},
				MaxChunk: rb.MaxWriteChunk,
				Logger:   rb.logger,
			}
		}
	}
	return next.ServeHTTP(w, r)
}

// errorWrapper wraps errors that are returned from Read()
// so that they can be associated with a proper status code.
type errorWrapper struct {
	io.ReadCloser
}

func (ew errorWrapper) Read(p []byte) (n int, err error) {
	n, err = ew.ReadCloser.Read(p)
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		err = caddyhttp.Error(http.StatusRequestEntityTooLarge, err)
	}
	return n, err
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*RequestBody)(nil)
