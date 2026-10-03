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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type readDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *readDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

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

// noError adapts a caddyhttp.Handler to a plain http.Handler for httptest.NewServer.
func noError(h caddyhttp.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h.ServeHTTP(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func TestTimeouts_ReadTimeoutIsIdleReset(t *testing.T) {
	const timeout = 150 * time.Millisecond

	tm := Timeouts{ReadTimeout: timeout}
	tm.logger = zap.NewNop()

	srv := httptest.NewServer(noError(caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return tm.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			_, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusRequestTimeout)
				return nil
			}
			w.WriteHeader(http.StatusOK)
			return nil
		}))
	})))
	defer srv.Close()

	// each gap is well under timeout, but the cumulative transfer time
	// is well over it; a hard (non-idle-reset) deadline would kill this
	body := &pacedReader{delay: timeout / 4, chunkSize: 8, chunkCount: 8}
	resp, err := http.Post(srv.URL, "application/octet-stream", body)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTimeoutsStopsReadDeadlineBeforeReturning(t *testing.T) {
	tm := Timeouts{ReadTimeout: time.Second, logger: zap.NewNop()}
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	var body io.Reader

	err := tm.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		body = r.Body
		_, _ = body.Read(make([]byte, 1))
		return nil
	}))
	require.NoError(t, err)
	require.Len(t, w.deadlines, 1)
	assert.False(t, w.deadlines[0].IsZero())

	_, _ = io.Copy(io.Discard, body)
	assert.Len(t, w.deadlines, 1)
}

func TestTimeoutsSkipsDrainDeadlineWithoutBody(t *testing.T) {
	tm := Timeouts{ReadTimeout: time.Second, logger: zap.NewNop()}
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err := tm.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	require.NoError(t, err)
	assert.Empty(t, w.deadlines)
}

func TestTimeouts_WriteMaxChunkOverride(t *testing.T) {
	const size = 10000
	const maxChunk = 100

	tm := Timeouts{WriteTimeout: time.Second, MaxWriteChunk: maxChunk}
	tm.logger = zap.NewNop()

	srv := httptest.NewServer(noError(caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return tm.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			_, err := w.Write(make([]byte, size))
			return err
		}))
	})))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	assert.EqualValues(t, size, n)
}

// TestTimeoutsTakePrecedence checks that the read timeout of the most
// specific scope applies: a timeouts handler over the server-wide idle
// timeout, and an inner timeouts handler over an outer one.
func TestTimeoutsTakePrecedence(t *testing.T) {
	const short = 100 * time.Millisecond
	const long = 2 * time.Second
	const pause = 300 * time.Millisecond

	for i, tc := range []struct {
		name     string
		server   time.Duration
		outer    time.Duration
		inner    time.Duration
		expected int
	}{
		{name: "route extends server-wide", server: short, inner: long, expected: http.StatusOK},
		{name: "route shortens server-wide", server: long, inner: short, expected: http.StatusRequestTimeout},
		{name: "inner route extends outer", outer: short, inner: long, expected: http.StatusOK},
		{name: "inner route shortens outer", outer: long, inner: short, expected: http.StatusRequestTimeout},
		{name: "inner route extends outer and server-wide", server: short, outer: short, inner: long, expected: http.StatusOK},
	} {
		var handler caddyhttp.Handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				w.WriteHeader(http.StatusRequestTimeout)
				return nil
			}
			w.WriteHeader(http.StatusOK)
			return nil
		})
		for _, timeout := range []time.Duration{tc.inner, tc.outer} {
			if timeout == 0 {
				continue
			}
			tm := Timeouts{ReadTimeout: timeout, logger: zap.NewNop()}
			next := handler
			handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return tm.ServeHTTP(w, r, next)
			})
		}

		srv := httptest.NewServer(noError(caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// stand in for the server-wide idle timeout
			if tc.server > 0 {
				reader := &caddyhttp.IdleTimeoutReader{
					ReadCloser: r.Body,
					Ctrl:       http.NewResponseController(w),
					Deadline:   caddyhttp.IdleDeadline{Start: time.Now(), Timeout: tc.server},
					Logger:     zap.NewNop(),
				}
				defer reader.HandlerDone()
				r.Body = reader
				r = r.WithContext(caddyhttp.ContextWithIdleTimeouts(r.Context(), reader, nil))
			}
			return handler.ServeHTTP(w, r)
		})))

		body := &pacedReader{delay: pause, chunkSize: 8, chunkCount: 2}
		resp, err := http.Post(srv.URL, "application/octet-stream", body)
		if err != nil {
			// a timed out read may close the connection before a response
			if tc.expected != http.StatusRequestTimeout {
				t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
			}
		} else {
			resp.Body.Close()
			assert.Equal(t, tc.expected, resp.StatusCode, "Test %d (%s)", i, tc.name)
		}
		srv.Close()
	}
}

func TestTimeoutsOverrideServerWide(t *testing.T) {
	const serverTimeout = time.Hour
	const routeTimeout = time.Minute

	rec := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	reader := &caddyhttp.IdleTimeoutReader{
		ReadCloser: req.Body,
		Ctrl:       http.NewResponseController(rec),
		Deadline:   caddyhttp.IdleDeadline{Start: time.Now(), Timeout: serverTimeout},
		Logger:     zap.NewNop(),
	}
	req.Body = reader
	writer := &caddyhttp.IdleTimeoutWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: rec},
		Ctrl:                  http.NewResponseController(rec),
		Deadline:              caddyhttp.IdleDeadline{Start: time.Now(), Timeout: serverTimeout},
		MaxChunk:              1000,
		Logger:                zap.NewNop(),
	}
	req = req.WithContext(caddyhttp.ContextWithIdleTimeouts(req.Context(), reader, writer))

	tm := Timeouts{ReadTimeout: routeTimeout, WriteTimeout: routeTimeout, MaxWriteChunk: 100, logger: zap.NewNop()}
	err := tm.ServeHTTP(writer, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// overridden in place rather than wrapped again
		assert.Same(t, writer, w)
		assert.Same(t, reader, r.Body)
		assert.Equal(t, routeTimeout, writer.Deadline.Timeout)
		assert.Equal(t, 100, writer.MaxChunk)

		before := time.Now()
		_, err := r.Body.Read(make([]byte, 1))
		require.NoError(t, err)
		require.Len(t, rec.deadlines, 1)
		assert.WithinRange(t, rec.deadlines[0], before.Add(routeTimeout), time.Now().Add(routeTimeout))
		return nil
	}))
	require.NoError(t, err)

	// the server-wide settings are back once the handler returns, and
	// the armed read deadline was moved to them
	assert.Equal(t, serverTimeout, writer.Deadline.Timeout)
	assert.Equal(t, 1000, writer.MaxChunk)
	require.Len(t, rec.deadlines, 2)
	assert.WithinRange(t, rec.deadlines[1], time.Now().Add(serverTimeout-time.Second), time.Now().Add(serverTimeout))

	before := time.Now()
	_, err = reader.Read(make([]byte, 1))
	require.NoError(t, err)
	require.Len(t, rec.deadlines, 3)
	assert.WithinRange(t, rec.deadlines[2], before.Add(serverTimeout), time.Now().Add(serverTimeout))
}

func TestTimeoutsKeepServerWideMaxWriteChunk(t *testing.T) {
	rec := httptest.NewRecorder()
	writer := &caddyhttp.IdleTimeoutWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: rec},
		Ctrl:                  http.NewResponseController(rec),
		Deadline:              caddyhttp.IdleDeadline{Timeout: time.Hour},
		MaxChunk:              1000,
		Logger:                zap.NewNop(),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(caddyhttp.ContextWithIdleTimeouts(req.Context(), nil, writer))

	tm := Timeouts{WriteTimeout: time.Minute, logger: zap.NewNop()}
	err := tm.ServeHTTP(writer, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		assert.Equal(t, 1000, writer.MaxChunk)
		return nil
	}))
	require.NoError(t, err)
}

// TestTimeoutsRearmReadDeadlineHTTP2 checks that a read deadline armed
// before a timeouts handler starts is moved to its timeout. On HTTP/2
// the deadline is a timer that fails the body when it fires, even with
// no read in flight, so it can't wait for the next read to be reset.
func TestTimeoutsRearmReadDeadlineHTTP2(t *testing.T) {
	const serverTimeout = 100 * time.Millisecond
	const routeTimeout = 2 * time.Second
	const pause = 300 * time.Millisecond

	tm := Timeouts{ReadTimeout: routeTimeout, logger: zap.NewNop()}
	srv := httptest.NewUnstartedServer(noError(caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// stand in for the server-wide idle timeout
		reader := &caddyhttp.IdleTimeoutReader{
			ReadCloser: r.Body,
			Ctrl:       http.NewResponseController(w),
			Deadline:   caddyhttp.IdleDeadline{Start: time.Now(), Timeout: serverTimeout},
			Logger:     zap.NewNop(),
		}
		defer reader.HandlerDone()
		r.Body = reader
		r = r.WithContext(caddyhttp.ContextWithIdleTimeouts(r.Context(), reader, nil))

		// read before the timeouts handler, arming the server-wide deadline
		if _, err := io.ReadFull(r.Body, make([]byte, 8)); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}
		return tm.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// pause longer than the server-wide timeout, but not the route's
			time.Sleep(pause)
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				w.WriteHeader(http.StatusRequestTimeout)
				return nil
			}
			w.WriteHeader(http.StatusOK)
			return nil
		}))
	})))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(make([]byte, 8))
		time.Sleep(pause + 100*time.Millisecond)
		_, _ = pw.Write(make([]byte, 8))
		_ = pw.Close()
	}()
	resp, err := srv.Client().Post(srv.URL, "application/octet-stream", pr)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
