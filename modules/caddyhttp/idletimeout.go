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

package caddyhttp

import (
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// idleTimeoutReader wraps a request body so that the read deadline is
// pushed forward before every Read call, instead of bounding the whole
// body transfer with a single hard deadline. This way, a slow but
// steadily-progressing upload is never killed, while a connection that
// stalls (no bytes for the duration of timeout) is. hardDeadline, if
// non-zero, caps how far the deadline can be pushed forward, so it
// doesn't silently defeat an explicitly configured ReadTimeout ceiling.
type idleTimeoutReader struct {
	io.ReadCloser
	ctrl         *http.ResponseController
	timeout      time.Duration
	hardDeadline time.Time
	unsupported  bool
	logger       *zap.Logger
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	if !r.unsupported {
		deadline := time.Now().Add(r.timeout)
		if !r.hardDeadline.IsZero() && deadline.After(r.hardDeadline) {
			deadline = r.hardDeadline
		}
		if err := r.ctrl.SetReadDeadline(deadline); err != nil {
			r.unsupported = true
			if c := r.logger.Check(zapcore.DebugLevel, "could not set read deadline"); c != nil {
				c.Write(zap.Error(err))
			}
		}
	}

	return r.ReadCloser.Read(p)
}

// idleTimeoutWriter wraps a ResponseWriter so that the write deadline is
// pushed forward before every Write call, the same way idleTimeoutReader
// does for reads. A handler that pauses between writes (e.g. streaming
// or SSE) is unaffected, since the deadline only bounds the duration of
// the write operation actually in flight. hardDeadline caps it the same
// way it does for idleTimeoutReader.
type idleTimeoutWriter struct {
	*ResponseWriterWrapper
	ctrl         *http.ResponseController
	timeout      time.Duration
	hardDeadline time.Time
	unsupported  bool
	logger       *zap.Logger
}

func (w *idleTimeoutWriter) resetDeadline() {
	if w.unsupported {
		return
	}

	deadline := time.Now().Add(w.timeout)
	if !w.hardDeadline.IsZero() && deadline.After(w.hardDeadline) {
		deadline = w.hardDeadline
	}
	if err := w.ctrl.SetWriteDeadline(deadline); err != nil {
		w.unsupported = true
		if c := w.logger.Check(zapcore.DebugLevel, "could not set write deadline"); c != nil {
			c.Write(zap.Error(err))
		}
	}
}

func (w *idleTimeoutWriter) Write(p []byte) (int, error) {
	w.resetDeadline()

	return w.ResponseWriterWrapper.Write(p)
}

func (w *idleTimeoutWriter) ReadFrom(r io.Reader) (int64, error) {
	w.resetDeadline()

	return w.ResponseWriterWrapper.ReadFrom(r)
}

// Interface guards
var (
	_ io.ReadCloser       = (*idleTimeoutReader)(nil)
	_ http.ResponseWriter = (*idleTimeoutWriter)(nil)
	_ io.ReaderFrom       = (*idleTimeoutWriter)(nil)
)
