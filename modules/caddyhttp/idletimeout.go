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
	"sync"
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
// The deadline is cleared after an error (most likely io.EOF) is encountered when reading the body
// to prevent context canceled error for h1 requests.
// see: https://github.com/caddyserver/caddy/issues/8103
type IdleTimeoutReader struct {
	io.ReadCloser
	Ctrl     *http.ResponseController
	Deadline IdleDeadline
	Logger   *zap.Logger

	// DrainDeadline makes HandlerDone arm a final idle deadline if
	// the body is unfinished, bounding net/http's post-handler drain.
	// Only HTTP/1 drains a request body on the connection after the
	// handler returns, so it is pointless (and costs a timer on
	// HTTP/2) for other protocols or requests without a body.
	DrainDeadline bool

	mu          sync.Mutex
	unsupported bool
	deadlineSet bool
	finished    bool
	terminalErr error
}

func (r *IdleTimeoutReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.terminalErr != nil {
		err := r.terminalErr
		r.mu.Unlock()
		return 0, err
	}
	if !r.finished && !r.unsupported {
		r.setDeadlineLocked("could not set read deadline")
	}
	r.mu.Unlock()

	n, err := r.ReadCloser.Read(p)

	r.mu.Lock()
	r.Deadline.transferred += int64(n)
	if err != nil {
		r.terminalErr = err
		if !r.finished {
			r.clearDeadlineLocked()
		}
	}
	r.mu.Unlock()

	return n, err
}

// HandlerDone prevents later body reads from using the response controller.
// If the body is not finished and DrainDeadline is set, it leaves an idle
// deadline armed for net/http's post-handler drain. It must be called before
// the installing handler returns.
func (r *IdleTimeoutReader) HandlerDone() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.finished {
		return
	}
	if r.terminalErr != nil {
		r.clearDeadlineLocked()
	} else if r.DrainDeadline && !r.deadlineSet && !r.unsupported {
		r.setDeadlineLocked("could not set final read deadline")
	}
	r.finished = true
}

func (r *IdleTimeoutReader) setDeadlineLocked(logMessage string) {
	if err := r.Ctrl.SetReadDeadline(r.Deadline.next()); err != nil {
		r.unsupported = true
		if c := r.Logger.Check(zapcore.DebugLevel, logMessage); c != nil {
			c.Write(zap.Error(err))
		}
		return
	}
	r.deadlineSet = true
}

func (r *IdleTimeoutReader) clearDeadlineLocked() {
	if !r.deadlineSet {
		return
	}
	if err := r.Ctrl.SetReadDeadline(time.Time{}); err != nil {
		r.unsupported = true
		if c := r.Logger.Check(zapcore.DebugLevel, "could not clear read deadline"); c != nil {
			c.Write(zap.Error(err))
		}
		return
	}
	r.deadlineSet = false
}

// IdleTimeoutWriter wraps a ResponseWriter with IdleDeadline, resetting
// the write deadline before every Write, ReadFrom and Flush call, the same
// way IdleTimeoutReader does for reads. With MinRate == 0, the deadline
// only bounds the write or flush actually in flight, so a handler that
// pauses between writes (e.g. streaming or SSE) is unaffected.
//
// That relies on a deadline left armed between writes being harmless,
// which holds for HTTP/1 and HTTP/3, where it is only checked by the
// next write on the connection or stream. On HTTP/2 the write deadline
// is a timer that resets the stream when it fires, even with no write
// in flight, so ClearBetweenWrites must be set for HTTP/2 requests
// (see #8118).
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

	// ClearBetweenWrites makes the writer clear its idle deadline after
	// every successful write or flush, putting back HardDeadline if any,
	// and arm a final one in HandlerDone if written data may still be
	// buffered. It is required for HTTP/2 and unnecessary (and costs a
	// deadline update per write) for other protocols.
	ClearBetweenWrites bool

	unsupported bool
	deadlineSet bool
	unflushed   bool
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
		return
	}
	w.deadlineSet = true
}

// clearDeadline replaces the idle deadline set by resetDeadline with
// HardDeadline, which is zero (no deadline) unless a hard ceiling is
// configured. It does nothing unless ClearBetweenWrites is set.
func (w *IdleTimeoutWriter) clearDeadline() {
	if !w.ClearBetweenWrites || !w.deadlineSet || w.unsupported {
		return
	}

	// once the hard deadline has passed, the deadline set by
	// resetDeadline (capped to it) has already expired; keep it
	if !w.Deadline.HardDeadline.IsZero() && !time.Now().Before(w.Deadline.HardDeadline) {
		return
	}

	if err := w.Ctrl.SetWriteDeadline(w.Deadline.HardDeadline); err != nil {
		w.unsupported = true
		if c := w.Logger.Check(zapcore.DebugLevel, "could not clear write deadline"); c != nil {
			c.Write(zap.Error(err))
		}
		return
	}
	w.deadlineSet = false
}

// HandlerDone arms a final idle deadline if ClearBetweenWrites is set
// and data written since the last flush may still be buffered, so that
// the flush net/http does after the handler returns is bounded too. It
// must be called before the installing handler returns, since the
// response controller can't be used after that.
func (w *IdleTimeoutWriter) HandlerDone() {
	if w.ClearBetweenWrites && w.unflushed && !w.deadlineSet {
		w.resetDeadline()
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
		if n > 0 {
			w.unflushed = true
		}
		if err != nil {
			return total, err
		}
	}
	w.clearDeadline()
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
		if n > 0 {
			w.unflushed = true
		}
		if err != nil {
			// the error may come from r rather than the client, in
			// which case the response can still be written to
			w.clearDeadline()
			return total, err
		}
		if n < int64(maxChunk) {
			w.clearDeadline()
			return total, nil
		}
	}
}

// FlushError flushes the underlying writer under the idle deadline. A
// small write may only fill a buffer, leaving the flush as the call
// that actually blocks on a client that stopped reading.
func (w *IdleTimeoutWriter) FlushError() error {
	w.resetDeadline()
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err != nil {
		return err
	}
	w.unflushed = false
	w.clearDeadline()
	return nil
}

// Interface guards
var (
	_ io.ReadCloser                   = (*IdleTimeoutReader)(nil)
	_ http.ResponseWriter             = (*IdleTimeoutWriter)(nil)
	_ io.ReaderFrom                   = (*IdleTimeoutWriter)(nil)
	_ interface{ FlushError() error } = (*IdleTimeoutWriter)(nil)
)
