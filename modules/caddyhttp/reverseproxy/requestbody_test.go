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

package reverseproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBodyNopCloserIfNotReadHTTP2Reset(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	body := &blockingRequestBody{reader: reader, entered: make(chan struct{})}
	aborted := make(chan struct{})
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("request did not use HTTP/2")
		}
		select {
		case <-body.entered:
			// Abort before sending response headers, while the request body is idle.
			close(aborted)
			panic(http.ErrAbortHandler)
		case <-r.Context().Done():
		}
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	client := upstream.Client()
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrapped := &bodyNopCloserIfNotRead{ReadCloser: body}
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { wrapped.connected.Store(true) }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, upstream.URL, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		select {
		case <-aborted:
		default:
			t.Fatalf("request returned before the upstream reset: %v", err)
		}
		if err == nil {
			t.Fatal("HTTP/2 reset did not return an error")
		}
	case <-time.After(5 * time.Second):
		// Release the blocked reader before the server's deferred cleanup.
		_ = reader.Close()
		cancel()
		t.Fatal("HTTP/2 reset did not interrupt the request body read")
	}
}

type blockingRequestBody struct {
	reader  *io.PipeReader
	entered chan struct{}
	once    sync.Once
}

func (b *blockingRequestBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	return b.reader.Read(p)
}

func (b *blockingRequestBody) Close() error { return b.reader.Close() }

type trackedRequestBody struct {
	io.Reader
	closed bool
	reads  int
}

func (b *trackedRequestBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

func (b *trackedRequestBody) Close() error {
	b.closed = true
	return nil
}

func TestBodyNopCloserIfNotRead(t *testing.T) {
	for _, tc := range []struct {
		name      string
		payload   string
		connected bool
		read      bool
	}{
		{name: "body without upstream connection remains available for retry", payload: "retry-payload"},
		{name: "body is closed once connected", payload: "request-body", connected: true, read: true},
		{name: "body is closed once connected even if unread", payload: "request-body", connected: true},
		{name: "empty body is closed after EOF", connected: true, read: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedRequestBody{Reader: strings.NewReader(tc.payload)}
			wrapped := &bodyNopCloserIfNotRead{ReadCloser: body}
			wrapped.connected.Store(tc.connected)
			if tc.read {
				if _, err := io.ReadAll(wrapped); err != nil {
					t.Fatal(err)
				}
			}
			if err := wrapped.Close(); err != nil {
				t.Fatal(err)
			}
			if body.closed != tc.connected {
				t.Fatalf("closed = %v, want %v", body.closed, tc.connected)
			}
			if !tc.connected {
				data, err := io.ReadAll(wrapped)
				if err != nil || string(data) != tc.payload {
					t.Fatalf("retry body = %q, error = %v", data, err)
				}
			}
			if tc.read && tc.payload == "" {
				reads := body.reads
				if n, err := wrapped.Read(make([]byte, 1)); n != 0 || err != io.EOF {
					t.Fatalf("read after EOF = %d, %v", n, err)
				}
				if body.reads != reads {
					t.Fatal("underlying body read again after initial EOF")
				}
			}
		})
	}
}
