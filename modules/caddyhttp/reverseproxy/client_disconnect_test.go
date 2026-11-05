package reverseproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestClientDisconnectRecordsStatus verifies that when the downstream client
// disconnects (its request context is canceled) before the upstream sends any
// response headers, the recorded status is 499 ("client closed request")
// rather than 0.
func TestClientDisconnectRecordsStatus(t *testing.T) {
	// backend that blocks until the client goes away, so it never gets
	// the chance to send response headers
	gotRequest := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(gotRequest)
		<-r.Context().Done()
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).WithContext(ctx)
	req = prepareTestRequest(req)

	rec := caddyhttp.NewResponseRecorder(httptest.NewRecorder(), nil, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return nil
		}))
	}()

	<-gotRequest
	cancel()
	wg.Wait()

	if got := rec.Status(); got != 499 {
		t.Errorf("expected status 499 after client disconnect, got %d", got)
	}
}

// failingWriter is a ResponseWriter whose body writes fail with err.
type failingWriter struct {
	*httptest.ResponseRecorder
	err error
}

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// failingReader is a response body from the backend whose reads fail with err.
type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

// TestClientCancelAbortLogLevel verifies that an HTTP/3 client canceling the
// request while the response is streamed is logged at debug level, while
// other errors that abort the response, including the same error coming from
// the backend, are still logged as warnings.
func TestClientCancelAbortLogLevel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		readErr bool // fail reading from the backend instead of writing to the client
		want    zapcore.Level
	}{
		{
			name: "http3 request canceled by client",
			err:  &http3.Error{Remote: true, ErrorCode: http3.ErrCodeRequestCanceled},
			want: zapcore.DebugLevel,
		},
		{
			name: "http3 request canceled locally",
			err:  &http3.Error{Remote: false, ErrorCode: http3.ErrCodeRequestCanceled},
			want: zapcore.WarnLevel,
		},
		{
			name: "other http3 error",
			err:  &http3.Error{Remote: true, ErrorCode: http3.ErrCodeInternalError},
			want: zapcore.WarnLevel,
		},
		{
			name: "other error",
			err:  errors.New("broken pipe"),
			want: zapcore.WarnLevel,
		},
		{
			name:    "http3 response canceled by backend",
			err:     &http3.Error{Remote: true, ErrorCode: http3.ErrCodeRequestCanceled},
			readErr: true,
			want:    zapcore.WarnLevel,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			h := &Handler{logger: zap.New(core)}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
			res := &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       fakeRWC{strings.NewReader("hello")},
			}
			var rw http.ResponseWriter = failingWriter{ResponseRecorder: httptest.NewRecorder(), err: tc.err}
			if tc.readErr {
				res.Body = fakeRWC{failingReader{tc.err}}
				rw = httptest.NewRecorder()
			}

			func() {
				defer func() {
					if r := recover(); r != http.ErrAbortHandler {
						t.Fatalf("expected panic with http.ErrAbortHandler, got %v", r)
					}
				}()
				_ = h.finalizeResponse(rw, req, res, caddy.NewReplacer(), fakeStart, h.logger, "example.test:443")
			}()

			entries := logs.FilterMessage("aborting with incomplete response").All()
			if len(entries) != 1 {
				t.Fatalf("expected 1 log entry, got %d", len(entries))
			}
			if got := entries[0].Level; got != tc.want {
				t.Errorf("log level = %s, want %s", got, tc.want)
			}
		})
	}
}
