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
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

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
