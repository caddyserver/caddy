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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestPrepareRequestNormalizesEmptyHTTP3Body(t *testing.T) {
	body := &trackingReadCloser{Reader: strings.NewReader("")}
	req := newHTTP3Request(body)
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("")), nil
	}
	req.TransferEncoding = []string{"chunked"}

	prepared, err := (Handler{}).prepareRequest(req, caddy.NewReplacer())
	if err != nil {
		t.Fatalf("preparing request: %v", err)
	}
	if prepared.ContentLength != 0 {
		t.Fatalf("ContentLength: got %d, want 0", prepared.ContentLength)
	}
	if prepared.Body != nil {
		t.Fatalf("Body: got %T, want nil", prepared.Body)
	}
	if prepared.GetBody != nil {
		t.Fatal("GetBody: got non-nil, want nil")
	}
	if prepared.TransferEncoding != nil {
		t.Fatalf("TransferEncoding: got %v, want nil", prepared.TransferEncoding)
	}
	if !body.closed {
		t.Fatal("original body was not closed")
	}
}

func TestPrepareRequestPreservesStreamingHTTP3Body(t *testing.T) {
	body := &trackingReadCloser{Reader: strings.NewReader("streamed body")}
	req := newHTTP3Request(body)

	prepared, err := (Handler{}).prepareRequest(req, caddy.NewReplacer())
	if err != nil {
		t.Fatalf("preparing request: %v", err)
	}
	got, err := io.ReadAll(prepared.Body)
	if err != nil {
		t.Fatalf("reading prepared body: %v", err)
	}
	if string(got) != "streamed body" {
		t.Fatalf("body: got %q, want %q", got, "streamed body")
	}
	if prepared.ContentLength != -1 {
		t.Fatalf("ContentLength: got %d, want -1", prepared.ContentLength)
	}
	if body.closed {
		t.Fatal("original body was closed before the prepared body")
	}
	if err := prepared.Body.Close(); err != nil {
		t.Fatalf("closing prepared body: %v", err)
	}
	if !body.closed {
		t.Fatal("closing prepared body did not close original body")
	}
}

func TestPrepareRequestReturnsHTTP3BodyCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := &trackingReadCloser{Reader: contextReader{ctx: ctx}}
	req := newHTTP3Request(body).WithContext(ctx)

	prepared, err := (Handler{}).prepareRequest(req, caddy.NewReplacer())
	if prepared != nil {
		t.Fatalf("prepared request: got non-nil, want nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error: got %v, want context.Canceled", err)
	}
	if !body.closed {
		t.Fatal("body was not closed after cancellation")
	}
}

func TestPrepareRequestReturnsHTTP3BodyReadError(t *testing.T) {
	wantErr := errors.New("read failed")
	body := &trackingReadCloser{readErr: wantErr}
	req := newHTTP3Request(body)

	prepared, err := (Handler{}).prepareRequest(req, caddy.NewReplacer())
	if prepared != nil {
		t.Fatalf("prepared request: got non-nil, want nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error: got %v, want %v", err, wantErr)
	}
	if !body.closed {
		t.Fatal("body was not closed after read error")
	}
}

func newHTTP3Request(body io.ReadCloser) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Proto = "HTTP/3.0"
	req.ProtoMajor = 3
	req.ProtoMinor = 0
	req.ContentLength = -1
	req.Body = body
	return caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, &caddyhttp.Server{})
}

type trackingReadCloser struct {
	io.Reader
	readErr error
	closed  bool
}

type contextReader struct {
	ctx context.Context
}

func (r contextReader) Read([]byte) (int, error) {
	return 0, r.ctx.Err()
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	if r.readErr != nil {
		return 0, r.readErr
	}
	return r.Reader.Read(p)
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}
