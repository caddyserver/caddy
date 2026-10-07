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
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
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

// idleOverride holds what restore needs to undo an override.
type idleOverride struct {
	prev IdleDeadline
	at   time.Time
}

// override replaces the timeout and minimum rate, counting the MinRate
// allowance from now, and returns what restore needs to put the
// previous settings back. HardDeadline is kept.
func (d *IdleDeadline) override(timeout time.Duration, minRate int64) idleOverride {
	o := idleOverride{prev: *d, at: time.Now()}
	d.Start = o.at
	d.Timeout = timeout
	d.MinRate = minRate
	d.transferred = 0
	return o
}

// restore puts back the settings replaced by override. The previous
// MinRate window is suspended while overridden: its start moves forward
// by the time spent overridden, and bytes transferred in the meantime
// don't count towards it, so the restored deadline can't already have
// expired because of time the override allowed.
func (d *IdleDeadline) restore(o idleOverride) {
	prev := o.prev
	prev.Start = prev.Start.Add(time.Since(o.at))
	*d = prev
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

	// ClearBetweenReads makes the reader put back HardDeadline (no
	// deadline unless a hard ceiling is configured) after every
	// successful read, so the idle deadline only bounds reads in
	// flight. It is required for HTTP/2, where the read deadline is a
	// timer that fails the body when it fires, even with no read in
	// flight: otherwise a handler that stops reading for longer than the
	// timeout (e.g. while an upstream is slow to accept the body) loses
	// the body, although the client is only held back by flow control.
	// Other protocols only check the deadline during a read.
	ClearBetweenReads bool

	mu          sync.Mutex
	unsupported bool
	armed       armedDeadline
	finished    bool
	terminalErr error
}

// armedDeadline is which read deadline IdleTimeoutReader has armed.
type armedDeadline uint8

const (
	// deadlineNone means no deadline is armed.
	deadlineNone armedDeadline = iota
	// deadlineIdle means the idle deadline from IdleDeadline.next is
	// armed.
	deadlineIdle
	// deadlineHard means only HardDeadline is armed, as put back
	// between reads with ClearBetweenReads.
	deadlineHard
)

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
	} else if r.ClearBetweenReads && !r.finished {
		r.releaseDeadlineLocked()
	}
	r.mu.Unlock()

	return n, err
}

// HandlerDone prevents later body reads from using the response controller.
// If the body is not finished and DrainDeadline is set, it leaves an idle
// deadline armed for net/http's post-handler drain. Otherwise, it clears a
// deadline left from a finished body or put back between reads. It must be
// called before the installing handler returns.
func (r *IdleTimeoutReader) HandlerDone() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.finished {
		return
	}
	if r.terminalErr != nil || r.armed == deadlineHard {
		r.clearDeadlineLocked()
	} else if r.DrainDeadline && r.armed != deadlineIdle && !r.unsupported {
		r.setDeadlineLocked("could not set final read deadline")
	}
	r.finished = true
}

// Override makes the reader use timeout and minRate instead of its own
// settings until the returned function is called, which puts them back.
// The MinRate allowance is counted from the call, and HardDeadline still
// applies. This lets a more specific scope, like the timeouts handler,
// take precedence over the settings the reader was created with. A
// deadline already armed is moved to the new settings both times, since
// on HTTP/2 it is a timer that fails the body when it fires, even with
// no read in flight.
func (r *IdleTimeoutReader) Override(timeout time.Duration, minRate int64) (restore func()) {
	r.mu.Lock()
	o := r.Deadline.override(timeout, minRate)
	r.rearmLocked()
	r.mu.Unlock()

	return func() {
		r.mu.Lock()
		r.Deadline.restore(o)
		r.rearmLocked()
		r.mu.Unlock()
	}
}

// rearmLocked moves an armed deadline to what the current settings give.
func (r *IdleTimeoutReader) rearmLocked() {
	if r.armed == deadlineIdle && !r.finished && !r.unsupported {
		r.setDeadlineLocked("could not set read deadline")
	}
}

func (r *IdleTimeoutReader) setDeadlineLocked(logMessage string) {
	if r.setReadDeadlineLocked(r.Deadline.next(), logMessage) {
		r.armed = deadlineIdle
	}
}

// setReadDeadlineLocked always sets the requested deadline: another handler
// may have changed it through its own response controller since our last call.
// It reports whether the deadline was set successfully.
func (r *IdleTimeoutReader) setReadDeadlineLocked(deadline time.Time, logMessage string) bool {
	if err := r.Ctrl.SetReadDeadline(deadline); err != nil {
		r.unsupported = true
		if c := r.Logger.Check(zapcore.DebugLevel, logMessage); c != nil {
			c.Write(zap.Error(err))
		}
		return false
	}
	return true
}

// releaseDeadlineLocked replaces the idle deadline with HardDeadline.
func (r *IdleTimeoutReader) releaseDeadlineLocked() {
	if r.armed != deadlineIdle || r.unsupported {
		return
	}

	// once the hard deadline has passed, the deadline set before the
	// read (capped to it) has already expired; keep it
	if !r.Deadline.HardDeadline.IsZero() && !time.Now().Before(r.Deadline.HardDeadline) {
		return
	}

	if !r.setReadDeadlineLocked(r.Deadline.HardDeadline, "could not release read deadline") {
		return
	}
	if r.Deadline.HardDeadline.IsZero() {
		r.armed = deadlineNone
	} else {
		r.armed = deadlineHard
	}
}

func (r *IdleTimeoutReader) clearDeadlineLocked() {
	if r.armed == deadlineNone {
		return
	}
	if !r.setReadDeadlineLocked(time.Time{}, "could not clear read deadline") {
		return
	}
	r.armed = deadlineNone
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
	// deadlineSet is whether the idle deadline is armed. clearDeadline
	// leaves HardDeadline armed, if any, which nothing needs to undo.
	deadlineSet bool
	unflushed   bool
}

func (w *IdleTimeoutWriter) resetDeadline() {
	if w.unsupported {
		return
	}

	if w.setWriteDeadline(w.Deadline.next(), "could not set write deadline") {
		w.deadlineSet = true
	}
}

// setWriteDeadline always sets the requested deadline: another handler may
// have changed it through its own response controller since our last call.
// It reports whether the deadline was set successfully.
func (w *IdleTimeoutWriter) setWriteDeadline(deadline time.Time, logMessage string) bool {
	if err := w.Ctrl.SetWriteDeadline(deadline); err != nil {
		w.unsupported = true
		if c := w.Logger.Check(zapcore.DebugLevel, logMessage); c != nil {
			c.Write(zap.Error(err))
		}
		return false
	}
	return true
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

	if !w.setWriteDeadline(w.Deadline.HardDeadline, "could not clear write deadline") {
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

// Override makes the writer use timeout, minRate and, if positive,
// maxChunk instead of its own settings until the returned function is
// called, which puts them back. The MinRate allowance is counted from
// the call, and HardDeadline still applies. This lets a more specific
// scope, like the timeouts handler, take precedence over the settings
// the writer was created with. A deadline already armed is moved to the
// new settings both times, since on HTTP/2 it is a timer that resets
// the stream when it fires.
func (w *IdleTimeoutWriter) Override(timeout time.Duration, minRate int64, maxChunk int) (restore func()) {
	o := w.Deadline.override(timeout, minRate)
	prevMaxChunk := w.MaxChunk
	if maxChunk > 0 {
		w.MaxChunk = maxChunk
	}
	w.rearm()

	return func() {
		w.Deadline.restore(o)
		w.MaxChunk = prevMaxChunk
		w.rearm()
	}
}

// rearm moves an armed deadline to what the current settings give.
func (w *IdleTimeoutWriter) rearm() {
	if w.deadlineSet {
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

// idleTimeouts holds the wrappers applying a request's idle timeouts.
type idleTimeouts struct {
	reader *IdleTimeoutReader
	writer *IdleTimeoutWriter
}

// idleTimeoutsCtxKey is the context key for idleTimeouts.
const idleTimeoutsCtxKey caddy.CtxKey = "idle_timeouts"

// IdleTimeoutsFromContext returns the IdleTimeoutReader and
// IdleTimeoutWriter that apply the idle timeouts of the request with
// context ctx. Either is nil if no idle timeout is applied that way. A
// handler with its own idle timeouts should Override these instead of
// wrapping the body or response writer again, since the wrapper closest
// to the connection sets the deadline last, and so would win.
func IdleTimeoutsFromContext(ctx context.Context) (*IdleTimeoutReader, *IdleTimeoutWriter) {
	it, _ := ctx.Value(idleTimeoutsCtxKey).(idleTimeouts)
	return it.reader, it.writer
}

// ContextWithIdleTimeouts returns a copy of ctx in which
// IdleTimeoutsFromContext returns reader and writer.
func ContextWithIdleTimeouts(ctx context.Context, reader *IdleTimeoutReader, writer *IdleTimeoutWriter) context.Context {
	return context.WithValue(ctx, idleTimeoutsCtxKey, idleTimeouts{reader: reader, writer: writer})
}

// Interface guards
var (
	_ io.ReadCloser                   = (*IdleTimeoutReader)(nil)
	_ http.ResponseWriter             = (*IdleTimeoutWriter)(nil)
	_ io.ReaderFrom                   = (*IdleTimeoutWriter)(nil)
	_ interface{ FlushError() error } = (*IdleTimeoutWriter)(nil)
)
