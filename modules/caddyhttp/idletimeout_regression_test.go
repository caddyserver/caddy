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

func TestIdleTimeoutReaderTerminalDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		keep bool
	}{
		{"timeout", fmt.Errorf("read body: %w", os.ErrDeadlineExceeded), true},
		{"EOF", io.EOF, false},
		{"other error", io.ErrUnexpectedEOF, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			r := &IdleTimeoutReader{
				ReadCloser:    terminalErrorBody{tc.err},
				Ctrl:          http.NewResponseController(w),
				Deadline:      IdleDeadline{Start: time.Now().Add(-time.Second), Timeout: 100 * time.Millisecond, MinRate: 1},
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
				require.False(t, last.IsZero(), "timed-out read must retain a deadline")
				require.True(t, last.Before(time.Now()), "terminal read deadline must already be expired")
			} else {
				require.True(t, last.IsZero(), "non-timeout terminal read must clear deadline")
			}
		})
	}
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
