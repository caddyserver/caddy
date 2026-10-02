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

// DefaultMaxWriteChunk is used by IdleTimeoutWriter when MaxChunk is zero.
// See IdleTimeoutWriter for why a limit is needed at all; nginx's
// analogous sendfile_max_chunk defaults to 2 MiB and is admin-tunable
// for the same reason this is exposed as a field rather than a constant.
const DefaultMaxWriteChunk = 64 * 1024

// IdleDeadline computes the next read/write deadline for the idle-reset
// mechanism shared by IdleTimeoutReader and IdleTimeoutWriter.
//
// With MinRate == 0, the deadline is simply pushed forward on every
// call (now+Timeout): a slow but steadily-progressing transfer is never
// killed, while a connection that stalls (no bytes for the duration of
// Timeout) is. This alone doesn't bound a transfer that trickles just
// enough data to never go idle.
//
// With MinRate > 0, the allowance instead grows from a fixed Start
// based on bytes transferred so far (1/MinRate seconds of extra
// allowance per byte), matching Apache mod_reqtimeout's MinRate: a
// trickle that doesn't sustain MinRate bytes/sec falls behind real
// time and gets cut, even though no single call ever stalls.
//
// HardDeadline, if non-zero, caps the result either way, so this can't
// silently defeat an explicitly configured ReadTimeout/WriteTimeout
// ceiling.
type IdleDeadline struct {
	Start        time.Time
	Timeout      time.Duration
	MinRate      int64
	HardDeadline time.Time

	transferred int64
}

func (d *IdleDeadline) next() (deadline time.Time) {
	if d.MinRate > 0 {
		credit := time.Duration(d.transferred) * time.Second / time.Duration(d.MinRate)
		deadline = d.Start.Add(d.Timeout + credit)
	} else {
		deadline = time.Now().Add(d.Timeout)
	}
	if !d.HardDeadline.IsZero() && deadline.After(d.HardDeadline) {
		deadline = d.HardDeadline
	}

	return
}

// IdleTimeoutReader wraps a request body with IdleDeadline, resetting
// the read deadline before every Read call instead of bounding the
// whole body transfer with a single hard deadline.
type IdleTimeoutReader struct {
	io.ReadCloser
	Ctrl     *http.ResponseController
	Deadline IdleDeadline
	Logger   *zap.Logger

	unsupported bool
}

func (r *IdleTimeoutReader) Read(p []byte) (int, error) {
	if !r.unsupported {
		if err := r.Ctrl.SetReadDeadline(r.Deadline.next()); err != nil {
			r.unsupported = true
			if c := r.Logger.Check(zapcore.DebugLevel, "could not set read deadline"); c != nil {
				c.Write(zap.Error(err))
			}
		}
	}

	n, err := r.ReadCloser.Read(p)
	r.Deadline.transferred += int64(n)

	return n, err
}

// IdleTimeoutWriter wraps a ResponseWriter with IdleDeadline, resetting
// the write deadline before every Write call, the same way
// IdleTimeoutReader does for reads. A handler that pauses between
// writes (e.g. streaming or SSE) is unaffected, since with MinRate == 0
// the deadline only bounds the duration of the write actually in flight.
//
// MaxChunk bounds how much a single underlying Write/ReadFrom call is
// allowed to cover; zero uses DefaultMaxWriteChunk. SetWriteDeadline
// bounds the whole call it precedes, not just a stall within it:
// net.Conn.Write loops internally until the entire buffer is sent
// (unlike Read, which returns after one syscall), and
// ResponseWriter.ReadFrom hands the entire remaining source to the
// connection in one call, be it via sendfile or an internal buffered
// copy loop. Without chunking, a single large Write or a large body
// copied via io.Copy would have its whole transfer bounded by one
// deadline, silently truncating a slow-but-healthy transfer exactly
// like a hard WriteTimeout would. A 64 KiB default still preserves
// most of the sendfile fast path's benefit (net/sendfile.go
// special-cases *io.LimitedReader to keep using sendfile per chunk).
type IdleTimeoutWriter struct {
	*ResponseWriterWrapper
	Ctrl     *http.ResponseController
	Deadline IdleDeadline
	MaxChunk int
	Logger   *zap.Logger

	unsupported bool
}

func (w *IdleTimeoutWriter) resetDeadline() {
	if w.unsupported {
		return
	}

	if err := w.Ctrl.SetWriteDeadline(w.Deadline.next()); err != nil {
		w.unsupported = true
		if c := w.Logger.Check(zapcore.DebugLevel, "could not set write deadline"); c != nil {
			c.Write(zap.Error(err))
		}
	}
}

func (w *IdleTimeoutWriter) maxChunk() int {
	if w.MaxChunk > 0 {
		return w.MaxChunk
	}
	return DefaultMaxWriteChunk
}

func (w *IdleTimeoutWriter) Write(p []byte) (int, error) {
	maxChunk := w.maxChunk()
	var total int
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		w.resetDeadline()
		n, err := w.ResponseWriterWrapper.Write(chunk)
		total += n
		w.Deadline.transferred += int64(n)
		p = p[n:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (w *IdleTimeoutWriter) ReadFrom(r io.Reader) (int64, error) {
	maxChunk := w.maxChunk()
	var total int64
	for {
		w.resetDeadline()
		n, err := w.ResponseWriterWrapper.ReadFrom(io.LimitReader(r, int64(maxChunk)))
		total += n
		w.Deadline.transferred += n
		if err != nil {
			return total, err
		}
		if n < int64(maxChunk) {
			return total, nil
		}
	}
}

// Interface guards
var (
	_ io.ReadCloser       = (*IdleTimeoutReader)(nil)
	_ http.ResponseWriter = (*IdleTimeoutWriter)(nil)
	_ io.ReaderFrom       = (*IdleTimeoutWriter)(nil)
)
