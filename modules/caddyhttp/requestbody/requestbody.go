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
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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

	// EXPERIMENTAL. Subject to change/removal.
	ReadTimeout time.Duration `json:"read_timeout,omitempty"`

	// EXPERIMENTAL. Subject to change/removal.
	WriteTimeout time.Duration `json:"write_timeout,omitempty"`

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
	if r.Body == nil {
		return next.ServeHTTP(w, r)
	}
	if rb.MaxSize > 0 {
		r.Body = errorWrapper{http.MaxBytesReader(w, r.Body, rb.MaxSize)}
	}
	if rb.ReadTimeout > 0 || rb.WriteTimeout > 0 {
		//nolint:bodyclose
		rc := http.NewResponseController(w)
		if rb.ReadTimeout > 0 {
			if err := rc.SetReadDeadline(time.Now().Add(rb.ReadTimeout)); err != nil {
				if c := rb.logger.Check(zapcore.ErrorLevel, "could not set read deadline"); c != nil {
					c.Write(zap.Error(err))
				}
			}
		}
		if rb.WriteTimeout > 0 {
			if err := rc.SetWriteDeadline(time.Now().Add(rb.WriteTimeout)); err != nil {
				if c := rb.logger.Check(zapcore.ErrorLevel, "could not set write deadline"); c != nil {
					c.Write(zap.Error(err))
				}
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
	return
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*RequestBody)(nil)
