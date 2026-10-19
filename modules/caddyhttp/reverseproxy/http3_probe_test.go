package reverseproxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

type errReader struct {
	err error
}

func (e errReader) Read(p []byte) (int, error) {
	return 0, e.err
}

func (e errReader) Close() error {
	return nil
}

func TestNormalizeHTTP3EmptyBody(t *testing.T) {
	t.Run("empty_body_normalized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		req.Proto = "HTTP/3.0"
		req.ProtoMajor = 3
		req.ContentLength = -1
		req.Body = io.NopCloser(bytes.NewReader(nil))

		err := normalizeHTTP3EmptyBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.ContentLength != 0 {
			t.Errorf("expected ContentLength 0, got %d", req.ContentLength)
		}
		if req.Body != nil {
			t.Errorf("expected nil Body, got %v", req.Body)
		}
		if req.GetBody != nil {
			t.Errorf("expected nil GetBody, got %v", req.GetBody)
		}
		if req.TransferEncoding != nil {
			t.Errorf("expected nil TransferEncoding, got %v", req.TransferEncoding)
		}
	})

	t.Run("streaming_body_preserved", func(t *testing.T) {
		const payload = "streaming body payload from http3"
		req := httptest.NewRequest(http.MethodPost, "https://example.com/upload", nil)
		req.Proto = "HTTP/3.0"
		req.ProtoMajor = 3
		req.ContentLength = -1
		req.Body = io.NopCloser(strings.NewReader(payload))

		err := normalizeHTTP3EmptyBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.ContentLength != -1 {
			t.Errorf("expected ContentLength -1, got %d", req.ContentLength)
		}
		if req.Body == nil {
			t.Fatalf("expected non-nil Body")
		}

		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if string(bodyBytes) != payload {
			t.Errorf("body content mismatch: got %q, want %q", string(bodyBytes), payload)
		}
	})

	t.Run("single_byte_body_preserved", func(t *testing.T) {
		const payload = "x"
		req := httptest.NewRequest(http.MethodGet, "https://example.com/get-with-body", nil)
		req.Proto = "HTTP/3.0"
		req.ProtoMajor = 3
		req.ContentLength = -1
		req.Body = io.NopCloser(strings.NewReader(payload))

		err := normalizeHTTP3EmptyBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.ContentLength != -1 {
			t.Errorf("expected ContentLength -1, got %d", req.ContentLength)
		}
		if req.Body == nil {
			t.Fatalf("expected non-nil Body")
		}

		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if string(bodyBytes) != payload {
			t.Errorf("body content mismatch: got %q, want %q", string(bodyBytes), payload)
		}
	})

	t.Run("read_error_fails_closed", func(t *testing.T) {
		expectedErr := errors.New("network disconnect")
		req := httptest.NewRequest(http.MethodGet, "https://example.com/fail", nil)
		req.Proto = "HTTP/3.0"
		req.ProtoMajor = 3
		req.ContentLength = -1
		req.Body = errReader{err: expectedErr}

		err := normalizeHTTP3EmptyBody(req)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected wrapped error %v, got %v", expectedErr, err)
		}
	})

	t.Run("http1_and_http2_ignored", func(t *testing.T) {
		for _, proto := range []struct {
			name  string
			major int
		}{
			{"HTTP/1.1", 1},
			{"HTTP/2.0", 2},
		} {
			t.Run(proto.name, func(t *testing.T) {
				body := io.NopCloser(bytes.NewReader(nil))
				req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
				req.Proto = proto.name
				req.ProtoMajor = proto.major
				req.ContentLength = -1
				req.Body = body

				err := normalizeHTTP3EmptyBody(req)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if req.ContentLength != -1 {
					t.Errorf("expected ContentLength -1 for %s, got %d", proto.name, req.ContentLength)
				}
				if req.Body != body {
					t.Errorf("expected Body to remain untouched for %s", proto.name)
				}
			})
		}
	})

	t.Run("known_content_length_ignored", func(t *testing.T) {
		body := io.NopCloser(bytes.NewReader(nil))
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		req.Proto = "HTTP/3.0"
		req.ProtoMajor = 3
		req.ContentLength = 10
		req.Body = body

		err := normalizeHTTP3EmptyBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.ContentLength != 10 {
			t.Errorf("expected ContentLength 10, got %d", req.ContentLength)
		}
		if req.Body != body {
			t.Errorf("expected Body to remain untouched")
		}
	})

	t.Run("trailers_ignored", func(t *testing.T) {
		body := io.NopCloser(bytes.NewReader(nil))
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		req.Proto = "HTTP/3.0"
		req.ProtoMajor = 3
		req.ContentLength = -1
		req.Trailer = http.Header{"X-Trailer": []string{"some-val"}}
		req.Body = body

		err := normalizeHTTP3EmptyBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.ContentLength != -1 {
			t.Errorf("expected ContentLength -1, got %d", req.ContentLength)
		}
		if req.Body != body {
			t.Errorf("expected Body to remain untouched")
		}
	})
}

func TestPrepareRequest_HTTP3EmptyBody(t *testing.T) {
	h := Handler{}
	repl := caddy.NewReplacer()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.Proto = "HTTP/3.0"
	req.ProtoMajor = 3
	req.ContentLength = -1
	req.Body = io.NopCloser(bytes.NewReader(nil))

	prepared, err := h.prepareRequest(req, repl)
	if err != nil {
		t.Fatalf("prepareRequest failed: %v", err)
	}

	if prepared.ContentLength != 0 {
		t.Errorf("expected prepared ContentLength 0, got %d", prepared.ContentLength)
	}
	if prepared.Body != nil {
		t.Errorf("expected nil Body, got %v", prepared.Body)
	}
}
