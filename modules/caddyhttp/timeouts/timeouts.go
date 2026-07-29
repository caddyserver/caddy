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

package timeouts

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Timeouts{})
}

// Timeouts is a middleware that applies read/write idle timeouts, minimum
// transfer rates, and a write chunk size cap to routes matching this
// handler, independent of the server-wide equivalents.
type Timeouts struct {
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

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Timeouts) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.timeouts",
		New: func() caddy.Module { return new(Timeouts) },
	}
}

func (t *Timeouts) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger()
	return nil
}

func (t Timeouts) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if t.ReadTimeout <= 0 && t.WriteTimeout <= 0 {
		return next.ServeHTTP(w, r)
	}

	//nolint:bodyclose
	rc := http.NewResponseController(w)
	start := time.Now()

	if t.ReadTimeout > 0 && r.Body != nil {
		r.Body = &caddyhttp.IdleTimeoutReader{
			ReadCloser: r.Body,
			Ctrl:       rc,
			Deadline: caddyhttp.IdleDeadline{
				Start:   start,
				Timeout: t.ReadTimeout,
				MinRate: t.ReadMinRate,
			},
			Logger: t.logger,
		}
	}
	if t.WriteTimeout > 0 {
		w = &caddyhttp.IdleTimeoutWriter{
			ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
			Ctrl:                  rc,
			Deadline: caddyhttp.IdleDeadline{
				Start:   start,
				Timeout: t.WriteTimeout,
				MinRate: t.WriteMinRate,
			},
			MaxChunk: t.MaxWriteChunk,
			Logger:   t.logger,
		}
	}

	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Timeouts)(nil)
	_ caddyhttp.MiddlewareHandler = (*Timeouts)(nil)
)
