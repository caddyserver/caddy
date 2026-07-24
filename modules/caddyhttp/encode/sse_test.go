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

package encode_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
	caddygzip "github.com/caddyserver/caddy/v2/modules/caddyhttp/encode/gzip"
)

// recordingWriter records the moment WriteHeader reaches the underlying
// writer, so a test can distinguish "headers flushed to the client" from
// "headers still buffered inside the encoder".
type recordingWriter struct {
	http.ResponseWriter
	wroteHeader bool
	status      int
}

func (rw *recordingWriter) WriteHeader(status int) {
	if !rw.wroteHeader {
		rw.wroteHeader = true
		rw.status = status
	}
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *recordingWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func newSSEEncodeHandler(t *testing.T) *encode.Encode {
	t.Helper()
	enc := &encode.Encode{
		EncodingsRaw: caddy.ModuleMap{
			"gzip": caddyconfig.JSON(caddygzip.Gzip{}, nil),
		},
		Prefer: []string{"gzip"},
		// A large minimum_length means a normal small response would be
		// buffered (its header withheld) until enough bytes arrive; the SSE
		// path must bypass this so the handshake reaches the client.
		MinLength: 4096,
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	if err := enc.Provision(ctx); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if err := enc.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	return enc
}

// An SSE upstream typically writes headers and flushes to establish the
// event stream before any event body is available. The encode middleware
// must let those headers reach the client immediately rather than holding
// them for minimum_length content sniffing. See #6293.
func TestSSEHeadersFlushedBeforeBody(t *testing.T) {
	enc := newSSEEncodeHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	rec := &recordingWriter{ResponseWriter: httptest.NewRecorder()}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// At this point — before any event body is written — the client
		// must already have the response headers.
		if !rec.wroteHeader {
			t.Error("SSE response headers were not flushed to the client before the body")
		}
		if rec.status != http.StatusOK {
			t.Errorf("underlying status = %d, want 200", rec.status)
		}
		return nil
	})

	if err := enc.ServeHTTP(rec, r, next); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
}

// A normal (non-SSE) small response is still allowed to buffer its header
// for content sniffing — the SSE change must not force every response to
// flush its header early. This guards the scope of the fix.
func TestNonSSESmallResponseStillBuffersHeader(t *testing.T) {
	enc := newSSEEncodeHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	rec := &recordingWriter{ResponseWriter: httptest.NewRecorder()}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if rec.wroteHeader {
			t.Error("non-SSE response flushed its header early; SSE bypass leaked to normal responses")
		}
		return nil
	})

	if err := enc.ServeHTTP(rec, r, next); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
}
