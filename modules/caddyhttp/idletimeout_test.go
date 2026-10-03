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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type readDeadlineRecorder struct {
	*httptest.ResponseRecorder
	mu        sync.Mutex
	deadlines []time.Time
	failAt    int
}

func (w *readDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deadlines = append(w.deadlines, deadline)
	if len(w.deadlines) == w.failAt {
		return errors.New("deadline failure")
	}
	return nil
}

func (w *readDeadlineRecorder) snapshot() []time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Time(nil), w.deadlines...)
}

type blockingReadCloser struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingReadCloser) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func (*blockingReadCloser) Close() error { return nil }

// pacedReader emits chunkCount chunks of chunkSize bytes, sleeping delay
// before each one, simulating a client that trickles a request body.
type pacedReader struct {
	delay      time.Duration
	chunkSize  int
	chunkCount int
}

func (p *pacedReader) Read(b []byte) (int, error) {
	if p.chunkCount <= 0 {
		return 0, io.EOF
	}
	time.Sleep(p.delay)
	p.chunkCount--
	n := copy(b, make([]byte, p.chunkSize))
	return n, nil
}

func TestIdleTimeoutReader(t *testing.T) {
	const timeout = 150 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutReader{
			ReadCloser: r.Body,
			Ctrl:       http.NewResponseController(w),
			Deadline:   IdleDeadline{Timeout: timeout},
			Logger:     zap.NewNop(),
		}
		_, err := io.Copy(io.Discard, wrapped)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Run("slow but steadily progressing upload is not killed", func(t *testing.T) {
		// each gap is well under timeout, but the cumulative transfer
		// time is well over it; a hard deadline would kill this
		body := &pacedReader{delay: timeout / 4, chunkSize: 8, chunkCount: 8}
		resp, err := http.Post(srv.URL, "application/octet-stream", body)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("stalled upload is aborted", func(t *testing.T) {
		// a single gap that exceeds timeout must trip the deadline
		body := &pacedReader{delay: timeout * 4, chunkSize: 8, chunkCount: 2}
		resp, err := http.Post(srv.URL, "application/octet-stream", body)
		if err != nil {
			// the connection may also be reset outright, which is fine
			return
		}
		defer resp.Body.Close()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

func TestIdleTimeoutReaderClearsDeadlineAtEOF(t *testing.T) {
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := &IdleTimeoutReader{
		ReadCloser: io.NopCloser(strings.NewReader("body")),
		Ctrl:       http.NewResponseController(w),
		Deadline:   IdleDeadline{Timeout: time.Second},
		Logger:     zap.NewNop(),
	}

	_, err := io.Copy(io.Discard, r)
	require.NoError(t, err)
	deadlines := w.snapshot()
	require.NotEmpty(t, deadlines)
	assert.True(t, deadlines[len(deadlines)-1].IsZero())
}

func TestIdleTimeoutReaderHandlerDone(t *testing.T) {
	body := &blockingReadCloser{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := &IdleTimeoutReader{
		ReadCloser: body,
		Ctrl:       http.NewResponseController(w),
		Deadline:   IdleDeadline{Timeout: time.Second},
		Logger:     zap.NewNop(),
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = r.Read(make([]byte, 1))
	}()
	<-body.started

	r.HandlerDone()
	deadlines := w.snapshot()
	require.Len(t, deadlines, 1)
	assert.False(t, deadlines[0].IsZero())

	close(body.release)
	<-readDone
	_, _ = r.Read(make([]byte, 1))
	r.HandlerDone()
	assert.Len(t, w.snapshot(), len(deadlines))
}

func TestIdleTimeoutReaderHandlerDoneAfterResetFailure(t *testing.T) {
	w := &readDeadlineRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		failAt:           2,
	}
	r := &IdleTimeoutReader{
		ReadCloser: io.NopCloser(strings.NewReader("body")),
		Ctrl:       http.NewResponseController(w),
		Deadline:   IdleDeadline{Timeout: time.Second},
		Logger:     zap.NewNop(),
	}

	_, _ = r.Read(make([]byte, 1))
	_, _ = r.Read(make([]byte, 1))
	r.HandlerDone()

	deadlines := w.snapshot()
	require.Len(t, deadlines, 2)
	assert.False(t, deadlines[0].IsZero())
	assert.False(t, deadlines[1].IsZero())
}

func TestIdleTimeoutReaderHandlerDoneRetriesTerminalClear(t *testing.T) {
	w := &readDeadlineRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		failAt:           3,
	}
	r := &IdleTimeoutReader{
		ReadCloser: io.NopCloser(strings.NewReader("body")),
		Ctrl:       http.NewResponseController(w),
		Deadline:   IdleDeadline{Timeout: time.Second},
		Logger:     zap.NewNop(),
	}

	_, err := io.Copy(io.Discard, r)
	require.NoError(t, err)
	r.HandlerDone()

	deadlines := w.snapshot()
	require.Len(t, deadlines, 4)
	assert.False(t, deadlines[0].IsZero())
	assert.False(t, deadlines[1].IsZero())
	assert.True(t, deadlines[2].IsZero())
	assert.True(t, deadlines[3].IsZero())
}

func TestIdleTimeoutReaderHandlerDoneArmsDrain(t *testing.T) {
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := &IdleTimeoutReader{
		ReadCloser:    io.NopCloser(strings.NewReader("body")),
		Ctrl:          http.NewResponseController(w),
		Deadline:      IdleDeadline{Timeout: time.Second},
		Logger:        zap.NewNop(),
		DrainDeadline: true,
	}

	r.HandlerDone()
	deadlines := w.snapshot()
	require.Len(t, deadlines, 1)
	assert.False(t, deadlines[0].IsZero())
}

func TestIdleTimeoutReaderHandlerDoneWithoutDrainDeadline(t *testing.T) {
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := &IdleTimeoutReader{
		ReadCloser: io.NopCloser(strings.NewReader("body")),
		Ctrl:       http.NewResponseController(w),
		Deadline:   IdleDeadline{Timeout: time.Second},
		Logger:     zap.NewNop(),
	}

	r.HandlerDone()
	assert.Empty(t, w.snapshot())
}

func TestIdleTimeoutReaderAfterHandlerReturnsHTTP2(t *testing.T) {
	lateBody := make(chan io.ReadCloser, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutReader{
			ReadCloser: r.Body,
			Ctrl:       http.NewResponseController(w),
			Deadline:   IdleDeadline{Timeout: time.Second},
			Logger:     zap.NewNop(),
		}
		defer wrapped.HandlerDone()
		lateBody <- wrapped
		_, _ = io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	resp, err := srv.Client().Post(srv.URL, "text/plain", strings.NewReader("body"))
	require.NoError(t, err)
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, 2, resp.ProtoMajor)
	require.Equal(t, "ok", string(responseBody))

	readResult := make(chan error, 1)
	go func() {
		var result error
		defer func() {
			if recovered := recover(); recovered != nil {
				result = fmt.Errorf("late request-body read panicked: %v", recovered)
			}
			readResult <- result
		}()
		_, _ = io.Copy(io.Discard, <-lateBody)
	}()
	select {
	case err := <-readResult:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("late request-body read did not return")
	}
}

func TestIdleTimeoutReaderHandlerDonePreservesHTTP1Connection(t *testing.T) {
	const idle = 100 * time.Millisecond

	remoteAddresses := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutReader{
			ReadCloser:    r.Body,
			Ctrl:          http.NewResponseController(w),
			Deadline:      IdleDeadline{Timeout: idle},
			Logger:        zap.NewNop(),
			DrainDeadline: r.ProtoMajor == 1 && r.ContentLength != 0,
		}
		defer wrapped.HandlerDone()
		remoteAddresses <- r.RemoteAddr
		if r.Method == http.MethodPost {
			_, _ = wrapped.Read(make([]byte, 1))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	transport := &http.Transport{MaxConnsPerHost: 1}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()

	resp, err := client.Post(srv.URL, "text/plain", strings.NewReader("body"))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	firstAddress := <-remoteAddresses

	time.Sleep(3 * idle)
	resp, err = client.Get(srv.URL)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, firstAddress, <-remoteAddresses)
}

func TestIdleTimeoutReaderDeadlineClearedAfterBodyEOF(t *testing.T) {
	const idle = 150 * time.Millisecond

	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer upstream.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutReader{
			ReadCloser: r.Body,
			Ctrl:       http.NewResponseController(w),
			Deadline:   IdleDeadline{Timeout: idle},
			Logger:     zap.NewNop(),
		}
		defer wrapped.HandlerDone()

		upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstream.URL, wrapped)
		if err != nil {
			t.Error(err)
			return
		}
		upReq.ContentLength = r.ContentLength
		resp, err := http.DefaultClient.Do(upReq)
		if err != nil {
			t.Error(err)
			return
		}
		_ = resp.Body.Close()

		select {
		case <-r.Context().Done():
			w.WriteHeader(http.StatusTeapot)
		case <-time.After(3 * idle):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/octet-stream", strings.NewReader("{}"))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIdleTimeoutReader_HardDeadlineCapsIdleReset(t *testing.T) {
	const idle = 500 * time.Millisecond
	const hard = 200 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutReader{
			ReadCloser: r.Body,
			Ctrl:       http.NewResponseController(w),
			Deadline: IdleDeadline{
				Timeout:      idle,
				HardDeadline: time.Now().Add(hard),
			},
			Logger: zap.NewNop(),
		}
		_, err := io.Copy(io.Discard, wrapped)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// each gap is under the idle timeout, so the connection is never
	// idle, but the cumulative transfer time exceeds hardDeadline: an
	// explicit hard ceiling must still cut it off despite the ongoing
	// idle-reset activity
	body := &pacedReader{delay: hard, chunkSize: 8, chunkCount: 8}
	resp, err := http.Post(srv.URL, "application/octet-stream", body)
	if err != nil {
		// the connection may also be reset outright, which is fine
		return
	}
	defer resp.Body.Close()
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

func TestIdleTimeoutReader_MinRateCatchesTrickle(t *testing.T) {
	const idle = 250 * time.Millisecond
	const chunkDelay = 150 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutReader{
			ReadCloser: r.Body,
			Ctrl:       http.NewResponseController(w),
			Deadline: IdleDeadline{
				Start:   time.Now(),
				Timeout: idle,
				// a huge min rate means even a full-size read call
				// earns virtually no extra credit, so a byte-sized
				// trickle can't keep the connection alive past idle
				MinRate: 100_000_000,
			},
			Logger: zap.NewNop(),
		}
		_, err := io.Copy(io.Discard, wrapped)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// each individual gap (150ms) is under the idle window (250ms), so
	// pure idle-reset alone would never trip; MinRate must still catch
	// this trickle since it never earns meaningful credit
	body := &pacedReader{delay: chunkDelay, chunkSize: 1, chunkCount: 6}
	resp, err := http.Post(srv.URL, "application/octet-stream", body)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

func TestIdleTimeoutReader_MinRateAllowsSustainedRate(t *testing.T) {
	const idle = 250 * time.Millisecond
	const chunkDelay = 100 * time.Millisecond
	const minRate = 1000 // bytes/second

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutReader{
			ReadCloser: r.Body,
			Ctrl:       http.NewResponseController(w),
			Deadline: IdleDeadline{
				Start:   time.Now(),
				Timeout: idle,
				MinRate: minRate,
			},
			Logger: zap.NewNop(),
		}
		_, err := io.Copy(io.Discard, wrapped)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 200 bytes every 100ms is 2000 bytes/second, comfortably above the
	// 1000 bytes/second minRate, so credit earned per chunk (200ms)
	// outpaces the real time elapsed per chunk (100ms): this transfer
	// must complete despite exceeding the idle window cumulatively
	body := &pacedReader{delay: chunkDelay, chunkSize: 200, chunkCount: 8}
	resp, err := http.Post(srv.URL, "application/octet-stream", body)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIdleTimeoutWriter(t *testing.T) {
	const timeout = 150 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutWriter{
			ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: w},
			Ctrl:                  http.NewResponseController(w),
			Deadline:              IdleDeadline{Timeout: timeout},
			Logger:                zap.NewNop(),
		}
		flusher, _ := wrapped.ResponseWriterWrapper.ResponseWriter.(http.Flusher)
		for range 8 {
			time.Sleep(timeout / 4)
			_, err := wrapped.Write(make([]byte, 8))
			if err != nil {
				t.Errorf("unexpected write error: %v", err)
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer srv.Close()

	// each write gap is well under timeout, but the cumulative streaming
	// time is well over it; a hard deadline would kill this response
	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	assert.EqualValues(t, 64, n)
}

func TestIdleTimeoutWriter_HardDeadlineCapsIdleReset(t *testing.T) {
	const idle = 500 * time.Millisecond
	const hard = 200 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutWriter{
			ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: w},
			Ctrl:                  http.NewResponseController(w),
			Deadline: IdleDeadline{
				Timeout:      idle,
				HardDeadline: time.Now().Add(hard),
			},
			Logger: zap.NewNop(),
		}
		flusher, _ := wrapped.ResponseWriterWrapper.ResponseWriter.(http.Flusher)
		for range 8 {
			time.Sleep(hard)
			if _, err := wrapped.Write(make([]byte, 8)); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer srv.Close()

	// each write gap is under the idle timeout, so the connection is
	// never idle, but the cumulative streaming time exceeds
	// hardDeadline: an explicit hard ceiling must still cut it off,
	// whether that surfaces as a failed request, a truncated body, or
	// both
	resp, err := http.Get(srv.URL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil {
		assert.Less(t, n, int64(64))
	}
}

// TestIdleTimeoutWriter_Streaming covers #8118: on HTTP/2 the write
// deadline is a timer that resets the stream when it fires, so a
// deadline left armed between writes kills a stream that merely pauses.
func TestIdleTimeoutWriter_Streaming(t *testing.T) {
	const idle = 100 * time.Millisecond
	const interval = 250 * time.Millisecond
	const count = 3

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &IdleTimeoutWriter{
			ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: w},
			Ctrl:                  http.NewResponseController(w),
			Deadline:              IdleDeadline{Timeout: idle},
			Logger:                zap.NewNop(),
			ClearBetweenWrites:    r.ProtoMajor == 2,
		}
		defer wrapped.HandlerDone()
		wrapped.Header().Set("Content-Type", "text/event-stream")
		rc := http.NewResponseController(wrapped)

		for i := range count {
			time.Sleep(interval)
			if _, err := fmt.Fprintf(wrapped, "data: %d\n\n", i); err != nil {
				t.Logf("write error: %v", err)
				return
			}
			if err := rc.Flush(); err != nil {
				t.Logf("flush error: %v", err)
				return
			}
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 2, resp.ProtoMajor)

	scanner := bufio.NewScanner(resp.Body)
	var linesRead int
	for scanner.Scan() {
		linesRead++
	}
	require.NoError(t, scanner.Err())
	require.Equal(t, 2*count, linesRead)
}

// writeDeadlineRecorder records every write deadline set on it.
type writeDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *writeDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestIdleTimeoutWriter_ClearBetweenWrites(t *testing.T) {
	const idle = time.Hour
	hard := time.Now().Add(2 * time.Hour)

	// the values recorded for each SetWriteDeadline call
	const (
		idleSet  = "idle"
		zeroSet  = "zero"
		hardSet  = "hard"
		otherSet = "other"
	)

	for i, tc := range []struct {
		name     string
		clear    bool
		hard     bool
		ops      func(w *IdleTimeoutWriter) error
		expected []string
	}{
		{
			name:     "write keeps the deadline when not clearing",
			ops:      func(w *IdleTimeoutWriter) error { _, err := w.Write([]byte("x")); return err },
			expected: []string{idleSet},
		},
		{
			name:     "write clears the deadline",
			clear:    true,
			ops:      func(w *IdleTimeoutWriter) error { _, err := w.Write([]byte("x")); return err },
			expected: []string{idleSet, zeroSet},
		},
		{
			name:     "write puts back the hard deadline",
			clear:    true,
			hard:     true,
			ops:      func(w *IdleTimeoutWriter) error { _, err := w.Write([]byte("x")); return err },
			expected: []string{idleSet, hardSet},
		},
		{
			name:     "empty write leaves the deadline alone",
			clear:    true,
			hard:     true,
			ops:      func(w *IdleTimeoutWriter) error { _, err := w.Write(nil); return err },
			expected: nil,
		},
		{
			name:     "read from clears the deadline",
			clear:    true,
			ops:      func(w *IdleTimeoutWriter) error { _, err := w.ReadFrom(bytes.NewReader([]byte("x"))); return err },
			expected: []string{idleSet, zeroSet},
		},
		{
			name:     "flush is bounded by the idle deadline",
			ops:      func(w *IdleTimeoutWriter) error { return w.FlushError() },
			expected: []string{idleSet},
		},
		{
			name:     "flush clears the deadline",
			clear:    true,
			ops:      func(w *IdleTimeoutWriter) error { return w.FlushError() },
			expected: []string{idleSet, zeroSet},
		},
		{
			name:  "handler done arms a deadline for unflushed writes",
			clear: true,
			ops: func(w *IdleTimeoutWriter) error {
				_, err := w.Write([]byte("x"))
				w.HandlerDone()
				return err
			},
			expected: []string{idleSet, zeroSet, idleSet},
		},
		{
			name:  "handler done does nothing after a flush",
			clear: true,
			ops: func(w *IdleTimeoutWriter) error {
				if _, err := w.Write([]byte("x")); err != nil {
					return err
				}
				err := w.FlushError()
				w.HandlerDone()
				return err
			},
			expected: []string{idleSet, zeroSet, idleSet, zeroSet},
		},
		{
			name: "handler done does nothing when not clearing",
			ops: func(w *IdleTimeoutWriter) error {
				_, err := w.Write([]byte("x"))
				w.HandlerDone()
				return err
			},
			expected: []string{idleSet},
		},
	} {
		rec := &writeDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		w := &IdleTimeoutWriter{
			ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: rec},
			Ctrl:                  http.NewResponseController(rec),
			Deadline:              IdleDeadline{Timeout: idle},
			Logger:                zap.NewNop(),
			ClearBetweenWrites:    tc.clear,
		}
		if tc.hard {
			w.Deadline.HardDeadline = hard
		}

		before := time.Now()
		if err := tc.ops(w); err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
		}
		after := time.Now()

		var actual []string
		for _, d := range rec.deadlines {
			switch {
			case d.IsZero():
				actual = append(actual, zeroSet)
			case d.Equal(hard):
				actual = append(actual, hardSet)
			case !d.Before(before.Add(idle)) && !d.After(after.Add(idle)):
				actual = append(actual, idleSet)
			default:
				actual = append(actual, otherSet)
			}
		}
		assert.Equal(t, tc.expected, actual, "Test %d (%s)", i, tc.name)
	}
}

// readFromCounter is a fake http.ResponseWriter that records how many
// times ReadFrom was called on it and the size of the largest call, so
// tests can assert on chunking behavior deterministically instead of
// depending on real TCP timing.
type readFromCounter struct {
	*httptest.ResponseRecorder
	calls        int
	maxCall      int
	total        int64
	writeCalls   int
	maxWriteCall int
}

func (c *readFromCounter) SetWriteDeadline(time.Time) error { return nil }

func (c *readFromCounter) ReadFrom(r io.Reader) (int64, error) {
	c.calls++
	n, err := io.Copy(io.Discard, r)
	c.total += n
	if int(n) > c.maxCall {
		c.maxCall = int(n)
	}
	return n, err
}

func (c *readFromCounter) Write(p []byte) (int, error) {
	c.writeCalls++
	if len(p) > c.maxWriteCall {
		c.maxWriteCall = len(p)
	}
	return c.ResponseRecorder.Write(p)
}

func TestIdleTimeoutWriter_ReadFromChunksLargeTransfer(t *testing.T) {
	const size = DefaultMaxWriteChunk*3 + 100 // 3 full chunks plus a partial tail

	counter := &readFromCounter{ResponseRecorder: httptest.NewRecorder()}
	wrapped := &IdleTimeoutWriter{
		ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: counter},
		Ctrl:                  http.NewResponseController(counter),
		Deadline:              IdleDeadline{Timeout: time.Second},
		Logger:                zap.NewNop(),
	}

	n, err := wrapped.ReadFrom(bytes.NewReader(make([]byte, size)))
	require.NoError(t, err)
	assert.EqualValues(t, size, n)
	assert.EqualValues(t, size, counter.total)
	assert.LessOrEqual(t, counter.maxCall, DefaultMaxWriteChunk,
		"no single underlying ReadFrom call should cover more than DefaultMaxWriteChunk bytes, "+
			"since SetWriteDeadline bounds the whole call it precedes, not just a stall within it")
	assert.Equal(t, 4, counter.calls, "expected 3 full chunks plus a partial tail chunk")
}

func TestIdleTimeoutWriter_WriteChunksLargePayload(t *testing.T) {
	const size = DefaultMaxWriteChunk*2 + 1

	counter := &readFromCounter{ResponseRecorder: httptest.NewRecorder()}
	wrapped := &IdleTimeoutWriter{
		ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: counter},
		Ctrl:                  http.NewResponseController(counter),
		Deadline:              IdleDeadline{Timeout: time.Second},
		Logger:                zap.NewNop(),
	}

	n, err := wrapped.Write(make([]byte, size))
	require.NoError(t, err)
	assert.EqualValues(t, size, n)
	assert.EqualValues(t, size, counter.ResponseRecorder.Body.Len())
	assert.LessOrEqual(t, counter.maxWriteCall, DefaultMaxWriteChunk,
		"no single underlying Write call should cover more than DefaultMaxWriteChunk bytes")
	assert.Equal(t, 3, counter.writeCalls, "expected 2 full chunks plus a 1-byte tail chunk")
}

func TestIdleTimeoutWriter_MaxChunkOverride(t *testing.T) {
	const size = 1000
	const maxChunk = 100

	counter := &readFromCounter{ResponseRecorder: httptest.NewRecorder()}
	wrapped := &IdleTimeoutWriter{
		ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: counter},
		Ctrl:                  http.NewResponseController(counter),
		Deadline:              IdleDeadline{Timeout: time.Second},
		MaxChunk:              maxChunk,
		Logger:                zap.NewNop(),
	}

	n, err := wrapped.Write(make([]byte, size))
	require.NoError(t, err)
	assert.EqualValues(t, size, n)
	assert.LessOrEqual(t, counter.maxWriteCall, maxChunk,
		"a configured MaxChunk should override DefaultMaxWriteChunk")
	assert.Equal(t, size/maxChunk, counter.writeCalls)
}
