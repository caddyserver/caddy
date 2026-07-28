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
		wrapped := &idleTimeoutReader{
			ReadCloser: r.Body,
			ctrl:       http.NewResponseController(w),
			timeout:    timeout,
			logger:     zap.NewNop(),
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
		wrapped := &idleTimeoutReader{
			ReadCloser:   r.Body,
			ctrl:         http.NewResponseController(w),
			timeout:      idle,
			hardDeadline: time.Now().Add(hard),
			logger:       zap.NewNop(),
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

func TestIdleTimeoutWriter(t *testing.T) {
	const timeout = 150 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &idleTimeoutWriter{
			ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: w},
			ctrl:                  http.NewResponseController(w),
			timeout:               timeout,
			logger:                zap.NewNop(),
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
		wrapped := &idleTimeoutWriter{
			ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: w},
			ctrl:                  http.NewResponseController(w),
			timeout:               idle,
			hardDeadline:          time.Now().Add(hard),
			logger:                zap.NewNop(),
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
