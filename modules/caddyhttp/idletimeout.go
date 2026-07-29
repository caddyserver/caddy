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

// idleDeadline computes the next read/write deadline for the idle-reset
// mechanism shared by idleTimeoutReader and idleTimeoutWriter.
//
// With minRate == 0, the deadline is simply pushed forward on every
// call (now+timeout): a slow but steadily-progressing transfer is never
// killed, while a connection that stalls (no bytes for the duration of
// timeout) is. This alone doesn't bound a transfer that trickles just
// enough data to never go idle.
//
// With minRate > 0, the allowance instead grows from a fixed start
// based on bytes transferred so far (1/minRate seconds of extra
// allowance per byte), matching Apache mod_reqtimeout's MinRate: a
// trickle that doesn't sustain minRate bytes/sec falls behind real
// time and gets cut, even though no single call ever stalls.
//
// hardDeadline, if non-zero, caps the result either way, so this can't
// silently defeat an explicitly configured ReadTimeout/WriteTimeout
// ceiling.
type idleDeadline struct {
	start        time.Time
	timeout      time.Duration
	minRate      int64
	hardDeadline time.Time
	transferred  int64
}

func (d *idleDeadline) next() (deadline time.Time) {
	if d.minRate > 0 {
		credit := time.Duration(d.transferred) * time.Second / time.Duration(d.minRate)
		deadline = d.start.Add(d.timeout + credit)
	} else {
		deadline = time.Now().Add(d.timeout)
	}
	if !d.hardDeadline.IsZero() && deadline.After(d.hardDeadline) {
		deadline = d.hardDeadline
	}

	return
}

// idleTimeoutReader wraps a request body with idleDeadline, resetting
// the read deadline before every Read call instead of bounding the
// whole body transfer with a single hard deadline.
type idleTimeoutReader struct {
	io.ReadCloser
	ctrl        *http.ResponseController
	deadline    idleDeadline
	unsupported bool
	logger      *zap.Logger
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	if !r.unsupported {
		if err := r.ctrl.SetReadDeadline(r.deadline.next()); err != nil {
			r.unsupported = true
			if c := r.logger.Check(zapcore.DebugLevel, "could not set read deadline"); c != nil {
				c.Write(zap.Error(err))
			}
		}
	}

	n, err := r.ReadCloser.Read(p)
	r.deadline.transferred += int64(n)

	return n, err
}

// idleTimeoutWriter wraps a ResponseWriter with idleDeadline, resetting
// the write deadline before every Write call, the same way
// idleTimeoutReader does for reads. A handler that pauses between
// writes (e.g. streaming or SSE) is unaffected, since with minRate == 0
// the deadline only bounds the duration of the write actually in flight.
type idleTimeoutWriter struct {
	*ResponseWriterWrapper
	ctrl        *http.ResponseController
	deadline    idleDeadline
	unsupported bool
	logger      *zap.Logger
}

func (w *idleTimeoutWriter) resetDeadline() {
	if w.unsupported {
		return
	}

	if err := w.ctrl.SetWriteDeadline(w.deadline.next()); err != nil {
		w.unsupported = true
		if c := w.logger.Check(zapcore.DebugLevel, "could not set write deadline"); c != nil {
			c.Write(zap.Error(err))
		}
	}
}

// maxWriteChunk bounds how much a single underlying Write/ReadFrom call
// is allowed to cover. SetWriteDeadline bounds the whole call it precedes,
// not just a stall within it: net.Conn.Write loops internally until the
// entire buffer is sent (unlike Read, which returns after one syscall),
// and ResponseWriter.ReadFrom hands the entire remaining source to the
// connection in one call, be it via sendfile or an internal buffered
// copy loop. Without chunking, a single large Write or a large body
// copied via io.Copy would have its whole transfer bounded by one
// deadline, silently truncating a slow-but-healthy transfer exactly
// like a hard WriteTimeout would. 64 KiB still preserves most of the
// sendfile fast path's benefit (net/sendfile.go special-cases
// *io.LimitedReader to keep using sendfile per chunk).
const maxWriteChunk = 64 * 1024

func (w *idleTimeoutWriter) Write(p []byte) (int, error) {
	var total int
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxWriteChunk {
			chunk = chunk[:maxWriteChunk]
		}
		w.resetDeadline()
		n, err := w.ResponseWriterWrapper.Write(chunk)
		total += n
		w.deadline.transferred += int64(n)
		p = p[n:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (w *idleTimeoutWriter) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	for {
		w.resetDeadline()
		n, err := w.ResponseWriterWrapper.ReadFrom(io.LimitReader(r, maxWriteChunk))
		total += n
		w.deadline.transferred += n
		if err != nil {
			return total, err
		}
		if n < maxWriteChunk {
			return total, nil
		}
	}
}

// Interface guards
var (
	_ io.ReadCloser       = (*idleTimeoutReader)(nil)
	_ http.ResponseWriter = (*idleTimeoutWriter)(nil)
	_ io.ReaderFrom       = (*idleTimeoutWriter)(nil)
)
