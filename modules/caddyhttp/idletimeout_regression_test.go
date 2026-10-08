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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// terminalErrorBody lets the deadline tests distinguish read timeouts from
// other terminal errors without relying on scheduling a real socket timeout.
type terminalErrorBody struct{ err error }

func (b terminalErrorBody) Read([]byte) (int, error) { return 0, b.err }
func (terminalErrorBody) Close() error               { return nil }

// earlyTimeoutError models an underlying reader timing out before the
// deadline installed by Caddy has expired.
type earlyTimeoutError struct{}

func (earlyTimeoutError) Error() string   { return "unrelated read timeout" }
func (earlyTimeoutError) Timeout() bool   { return true }
func (earlyTimeoutError) Temporary() bool { return true }

func TestIdleTimeoutReaderTerminalDeadline(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		offset time.Duration
		keep   bool
	}{
		{"expired timeout", fmt.Errorf("read body: %w", os.ErrDeadlineExceeded), -time.Second, true},
		{"early timeout", earlyTimeoutError{}, time.Hour, false},
		{"early wrapped deadline error", fmt.Errorf("early: %w", os.ErrDeadlineExceeded), time.Hour, false},
		{"EOF", io.EOF, -time.Second, false},
		{"other error", io.ErrUnexpectedEOF, -time.Second, false},
		{"context canceled", context.Canceled, -time.Second, false},
		{"generic error", fmt.Errorf("read failed"), -time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			r := &IdleTimeoutReader{
				ReadCloser:    terminalErrorBody{tc.err},
				Ctrl:          http.NewResponseController(w),
				Deadline:      IdleDeadline{Start: time.Now().Add(tc.offset), Timeout: 100 * time.Millisecond, MinRate: 1},
				Logger:        zap.NewNop(),
				DrainDeadline: true,
			}
			_, err := r.Read(make([]byte, 1))
			require.ErrorIs(t, err, tc.err)
			r.HandlerDone()

			deadlines := w.snapshot()
			require.NotEmpty(t, deadlines)
			last := deadlines[len(deadlines)-1]
			if tc.keep {
				require.False(t, last.IsZero(), "expired terminal read deadline must remain installed")
				require.True(t, last.Before(time.Now()), "preserved deadline must be expired")
			} else {
				require.True(t, last.IsZero(), "EOF, cancellations, and non-expired timeouts must clear deadline")
			}
		})
	}
}

func TestIdleTimeoutReaderTerminalDeadlineNotArmed(t *testing.T) {
	// No deadline must never be treated as an expired one, even when
	// the error happens to implement net.Error.Timeout.
	r := &IdleTimeoutReader{DrainDeadline: true}
	require.False(t, r.expiredTerminalReadDeadline(os.ErrDeadlineExceeded))
	require.False(t, r.expiredTerminalReadDeadline(earlyTimeoutError{}))

	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder(), failAt: 1}
	r = &IdleTimeoutReader{
		ReadCloser:    terminalErrorBody{os.ErrDeadlineExceeded},
		Ctrl:          http.NewResponseController(w),
		Deadline:      IdleDeadline{Start: time.Now().Add(-time.Second), Timeout: 100 * time.Millisecond, MinRate: 1},
		Logger:        zap.NewNop(),
		DrainDeadline: true,
	}
	_, err := r.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.True(t, r.unsupported)
	require.True(t, r.armedUntil.IsZero(), "unsuccessful SetReadDeadline must not be recorded")
	r.HandlerDone()
}

func timeoutWireHandler(timeout time.Duration, minRate int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reader := &IdleTimeoutReader{
			ReadCloser:        req.Body,
			Ctrl:              http.NewResponseController(w),
			Deadline:          IdleDeadline{Start: time.Now(), Timeout: timeout, MinRate: minRate},
			Logger:            zap.NewNop(),
			DrainDeadline:     req.ProtoMajor == 1 && req.ContentLength != 0,
			ClearBetweenReads: req.ProtoMajor == 2,
		}
		defer reader.HandlerDone()

		if _, err := io.Copy(io.Discard, reader); err != nil {
			http.Error(w, "request body timed out", http.StatusGatewayTimeout)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// The HTTP/1 server drains unread request bodies before writing its response.
// For sub-256 KiB bodies a cleared deadline can make that drain wait forever.
func TestIdleTimeoutReaderWireHTTP1TerminalTimeout(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		initial int
		minRate int64
		trickle bool
	}{
		{name: "stalled", size: 100 << 10, initial: 10 << 10},
		{name: "trickled below min rate", size: 80 << 10, initial: 1024, minRate: 32 << 10, trickle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const timeout = 180 * time.Millisecond
			srv := httptest.NewServer(timeoutWireHandler(timeout, tc.minRate))
			defer srv.Close()

			conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
			require.NoError(t, err)
			defer conn.Close()

			_, err = fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n", tc.size)
			require.NoError(t, err)
			_, err = conn.Write(bytes.Repeat([]byte{'x'}, tc.initial))
			require.NoError(t, err)

			stop := make(chan struct{})
			defer close(stop)
			var sent atomic.Int64
			sent.Store(int64(tc.initial))
			if tc.trickle {
				go func() {
					ticker := time.NewTicker(70 * time.Millisecond)
					defer ticker.Stop()
					for int(sent.Load()) < tc.size {
						select {
						case <-stop:
							return
						case <-ticker.C:
						}
						n, err := conn.Write(bytes.Repeat([]byte{'x'}, 1024))
						sent.Add(int64(n))
						if err != nil {
							return
						}
					}
				}()
			}

			// On the broken implementation, no response arrives until the
			// trickle finishes (5+ seconds), or indefinitely if stalled.
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
			require.NoError(t, err, "HTTP/1 response was blocked by post-handler drain")
			defer resp.Body.Close()
			require.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
			if tc.trickle {
				require.Less(t, sent.Load(), int64(tc.size), "response must arrive before the body finishes uploading")
			}
		})
	}
}

// The incomplete final chunk also exercises the HTTP/1 drain for requests
// whose ContentLength is unknown (Transfer-Encoding: chunked).
func TestIdleTimeoutReaderWireHTTP1ChunkedStalled(t *testing.T) {
	const timeout = 180 * time.Millisecond
	srv := httptest.NewServer(timeoutWireHandler(timeout, 0))
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)
	defer conn.Close()

	_, err = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n")
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	require.NoError(t, err, "chunked HTTP/1 upload must not block the error response")
	defer resp.Body.Close()
	require.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
}

// A timed-out, incompletely drained HTTP/1 request cannot share its
// connection with a subsequent request.
func TestIdleTimeoutReaderWireHTTP1NoReuseAfterTimeout(t *testing.T) {
	const timeout = 180 * time.Millisecond
	srv := httptest.NewServer(timeoutWireHandler(timeout, 0))
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)
	defer conn.Close()
	reader := bufio.NewReader(conn)

	_, err = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 102400\r\n\r\npartial")
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))

	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	require.NoError(t, err)
	require.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// Depending on TCP timing, either the write fails immediately
	// or a subsequent response read observes that the server closed.
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if err == nil {
		next, readErr := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if next != nil {
			next.Body.Close()
		}
		require.Error(t, readErr, "timed-out connection must not process another request")
	}
}

func TestIdleTimeoutReaderWireHTTP2TimeoutControl(t *testing.T) {
	const timeout = 180 * time.Millisecond
	srv := httptest.NewUnstartedServer(timeoutWireHandler(timeout, 0))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	body, writer := io.Pipe()
	stop := make(chan struct{})
	defer close(stop)
	defer writer.Close()
	go func() {
		_, _ = writer.Write(bytes.Repeat([]byte{'x'}, 10<<10))
		<-stop // keep the upload open until after the response arrives
	}()

	req, err := http.NewRequest(http.MethodPost, srv.URL, body)
	require.NoError(t, err)
	req.ContentLength = 100 << 10
	client := srv.Client()
	client.Timeout = 3 * time.Second
	resp, err := client.Do(req)
	require.NoError(t, err, "HTTP/2 must respond without waiting for an incomplete request body")
	defer resp.Body.Close()
	require.Equal(t, 2, resp.ProtoMajor)
	require.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
}
