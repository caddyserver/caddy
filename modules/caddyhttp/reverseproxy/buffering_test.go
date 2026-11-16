package reverseproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestBuffering(t *testing.T) {
	var (
		h  Handler
		zr zeroReader
	)
	type args struct {
		body  io.ReadCloser
		limit int64
	}
	tests := []struct {
		name        string
		args        args
		resultCheck func(io.ReadCloser, int64, args) bool
	}{
		{
			name: "0 limit, body is returned as is",
			args: args{
				body:  io.NopCloser(&zr),
				limit: 0,
			},
			resultCheck: func(res io.ReadCloser, read int64, args args) bool {
				return res == args.body && read == args.limit && read == 0
			},
		},
		{
			name: "negative limit, body is read completely",
			args: args{
				body:  io.NopCloser(io.LimitReader(&zr, 100)),
				limit: -1,
			},
			resultCheck: func(res io.ReadCloser, read int64, args args) bool {
				brc, ok := res.(*bodyReadCloser)
				return ok && brc.body == nil && brc.buf.Len() == 100 && read == 100
			},
		},
		{
			name: "positive limit, body is read partially",
			args: args{
				body:  io.NopCloser(io.LimitReader(&zr, 100)),
				limit: 50,
			},
			resultCheck: func(res io.ReadCloser, read int64, args args) bool {
				brc, ok := res.(*bodyReadCloser)
				return ok && brc.body != nil && brc.buf.Len() == 50 && read == 50
			},
		},
		{
			name: "positive limit, body is read completely",
			args: args{
				body:  io.NopCloser(io.LimitReader(&zr, 100)),
				limit: 101,
			},
			resultCheck: func(res io.ReadCloser, read int64, args args) bool {
				brc, ok := res.(*bodyReadCloser)
				return ok && brc.body == nil && brc.buf.Len() == 100 && read == 100
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, read := h.bufferedBody(tt.args.body, tt.args.limit)
			defer res.Close()
			if !tt.resultCheck(res, read, tt.args) {
				t.Error("Handler.bufferedBody() test failed")
				return
			}
		})
	}
}

// TestBufferingBoundary documents where a buffered body stops being fully
// buffered, which is what decides whether the caller can learn its length and
// set Content-Length. A body the size of the limit counts as partial: io.CopyN
// filling the buffer cannot be told apart from a body with more to come, and
// finding out would mean a blocking read on a stream that may never deliver.
func TestBufferingBoundary(t *testing.T) {
	const body = "0123456789"

	for limit := int64(1); limit <= int64(len(body))+2; limit++ {
		var h Handler
		res, read := h.bufferedBody(io.NopCloser(strings.NewReader(body)), limit)

		// Whatever the limit, the upstream must still receive every byte.
		got, err := io.ReadAll(res)
		if err != nil {
			t.Fatalf("limit %d: reading buffered body: %v", limit, err)
		}
		if string(got) != body {
			t.Errorf("limit %d: body changed: got %q, want %q", limit, got, body)
		}
		if err := res.Close(); err != nil {
			t.Errorf("limit %d: closing buffered body: %v", limit, err)
		}

		brc, ok := res.(*bodyReadCloser)
		if !ok {
			t.Fatalf("limit %d: expected a bodyReadCloser", limit)
		}
		wantFull := limit > int64(len(body))
		if gotFull := brc.body == nil; gotFull != wantFull {
			t.Errorf("limit %d: fully buffered = %v, want %v", limit, gotFull, wantFull)
		}
		if wantFull && read != int64(len(body)) {
			t.Errorf("limit %d: read %d bytes, want %d", limit, read, len(body))
		}
	}
}

// TestBufferingKeepsReadError checks that a body which fails partway through
// (a request_body max_size limit, a truncated upstream response) is not
// passed on as if it were complete.
func TestBufferingKeepsReadError(t *testing.T) {
	errRead := errors.New("read failed")

	for _, limit := range []int64{-1, 5, 100} {
		var h Handler
		body := io.NopCloser(io.MultiReader(strings.NewReader("0123456789"), iotest.ErrReader(errRead)))
		res, _ := h.bufferedBody(body, limit)

		got, err := io.ReadAll(res)
		if !errors.Is(err, errRead) {
			t.Errorf("limit %d: reading buffered body: got error %v, want %v", limit, err, errRead)
		}
		if string(got) != "0123456789" {
			t.Errorf("limit %d: got %q, want %q", limit, got, "0123456789")
		}

		brc, ok := res.(*bodyReadCloser)
		if !ok {
			t.Fatalf("limit %d: expected a bodyReadCloser", limit)
		}

		if brc.body == nil {
			t.Errorf("limit %d: body reported as fully buffered", limit)
		}
		res.Close()
	}
}

type bufferingTestBody struct {
	io.Reader
	closes atomic.Int32
	err    error
}

func (b *bufferingTestBody) Close() error {
	b.closes.Add(1)
	return b.err
}

func TestBufferedBodyCloseOwnership(t *testing.T) {
	const payload = "canary"
	const size = int64(len(payload))
	for _, limit := range []int64{-1, size - 1, size, size + 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			closeErr := errors.New("synthetic close error")
			original := &bufferingTestBody{Reader: strings.NewReader(payload), err: closeErr}
			body, _ := (Handler{}).bufferedBody(original, limit)
			b := body.(*bodyReadCloser)
			var wg sync.WaitGroup
			for range 32 {
				wg.Go(func() {
					err := body.Close()
					if b.body != nil && !errors.Is(err, closeErr) {
						t.Errorf("Close error = %v, want %v", err, closeErr)
					}
				})
			}
			wg.Wait()
			if got := original.closes.Load(); got != 1 {
				t.Fatalf("underlying Close called %d times, want 1", got)
			}
			if b.buf != nil || !b.closed {
				t.Fatal("closed body retained buffer ownership")
			}
			if n, err := body.Read(make([]byte, 32)); n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after release = %d, %v", n, err)
			}
		})
	}
}

func TestBufferedBodyReplayOwnership(t *testing.T) {
	const payload = "synthetic replay canary"
	body, _ := (Handler{}).bufferedBody(io.NopCloser(strings.NewReader(payload)), -1)
	owner := body.(*bodyReadCloser)
	defer owner.Close()
	first := &bufferedBodyReader{owner: owner}
	second := &bufferedBodyReader{owner: owner}
	if n, err := first.Read(make([]byte, 3)); n != 3 || err != nil {
		t.Fatalf("first read = %d, %v", n, err)
	}
	first.Close()
	got, err := io.ReadAll(second)
	if err != nil || string(got) != payload {
		t.Fatalf("replayed body = %q, %v", got, err)
	}
	owner.Close()
	for _, reader := range []io.ReadCloser{first, second, owner, &bufferedBodyReader{owner: owner}} {
		if n, err := reader.Read(make([]byte, 32)); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Errorf("read after release = %d, %v", n, err)
		}
		reader.Close()
	}
}

func TestBufferedBodyConcurrentReadClose(t *testing.T) {
	for _, limit := range []int64{-1, 4, 8} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			original := &bufferingTestBody{Reader: strings.NewReader("synthetic canary")}
			body, _ := (Handler{}).bufferedBody(original, limit)
			defer body.Close()
			var reader io.ReadCloser = body
			if limit == -1 {
				reader = &bufferedBodyReader{owner: body.(*bodyReadCloser)}
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() {
				<-start
				for range 64 {
					_, err := reader.Read(make([]byte, 1))
					if err != nil && err != io.EOF && !errors.Is(err, net.ErrClosed) {
						t.Errorf("concurrent read: %v", err)
					}
				}
			})
			for range 16 {
				wg.Go(func() {
					<-start
					body.Close()
				})
			}
			close(start)
			wg.Wait()
			if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after concurrent release = %d, %v", n, err)
			}
			if got := original.closes.Load(); got != 1 {
				t.Fatalf("underlying Close called %d times, want 1", got)
			}
		})
	}
}

type blockingBufferingBody struct {
	started chan struct{}
	closed  chan struct{}
}

func (b *blockingBufferingBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.closed
	return 0, net.ErrClosed
}

func (b *blockingBufferingBody) Close() error {
	close(b.closed)
	return nil
}

func TestBufferedBodyCloseUnblocksRead(t *testing.T) {
	original := &blockingBufferingBody{started: make(chan struct{}), closed: make(chan struct{})}
	body, _ := (Handler{}).bufferedBody(&struct {
		io.Reader
		io.Closer
	}{io.MultiReader(strings.NewReader("abcd"), original), original}, 4)
	defer body.Close()
	if n, err := body.Read(make([]byte, 4)); n != 4 || err != nil {
		t.Fatalf("buffer read = %d, %v", n, err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := body.Read(make([]byte, 4))
		done <- err
	}()
	select {
	case <-original.started:
	case <-time.After(5 * time.Second):
		t.Fatal("stream read did not start")
	}
	go body.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("stream read error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock stream read")
	}
}

func TestBufferedBodyRetiredAttempt(t *testing.T) {
	original := &bufferingTestBody{Reader: strings.NewReader("untouched canary")}
	attempt := &bodyNopCloserIfNotRead{ReadCloser: original}
	attempt.Close()
	if n, err := attempt.Read(make([]byte, 1)); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired attempt read = %d, %v", n, err)
	}
	if attempt.didRead() || original.closes.Load() != 0 {
		t.Fatal("retiring an unread attempt consumed or closed the stream")
	}
	next := &bodyNopCloserIfNotRead{ReadCloser: original}
	defer next.Close()
	got, err := io.ReadAll(next)
	if err != nil || string(got) != "untouched canary" {
		t.Fatalf("next attempt body = %q, %v", got, err)
	}
	attempt.Close()
	if original.closes.Load() != 0 {
		t.Fatal("late Close from a retired attempt closed the next attempt")
	}
}

type bufferingTestTransport func(*http.Request) (*http.Response, error)

func (f bufferingTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestBufferedBodyPartialReadNotRetried(t *testing.T) {
	for _, limit := range []int64{0, 4, -1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			original := &bufferingTestBody{Reader: strings.NewReader("synthetic canary")}
			req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", original))
			defer req.Body.Close()
			h := minimalHandler(1, &Upstream{Host: new(Host), Dial: "127.0.0.1:1"})
			h.RequestBuffers = limit
			var attempts int
			var retired io.ReadCloser
			transportErr := errors.New("forced failure after one byte")
			h.Transport = bufferingTestTransport(func(r *http.Request) (*http.Response, error) {
				attempts++
				retired = r.Body
				if n, err := r.Body.Read(make([]byte, 1)); n != 1 || err != nil {
					t.Errorf("prefix read = %d, %v", n, err)
				}
				r.Body.Close()
				return nil, transportErr
			})
			if err := h.ServeHTTP(httptest.NewRecorder(), req, nil); !errors.Is(err, transportErr) {
				t.Fatalf("proxy error = %v, want %v", err, transportErr)
			}
			want := 1
			if limit == -1 {
				want = 2
			}
			if attempts != want {
				t.Fatalf("attempts = %d, want %d", attempts, want)
			}
			if n, err := retired.Read(make([]byte, 1)); n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("retired transport read = %d, %v", n, err)
			}
		})
	}
}

func TestBufferedBodyTransportRetries(t *testing.T) {
	const payload = "synthetic transport canary"
	const size = int64(len(payload))
	for _, failure := range []string{"dial", "consumed", "response", "truncated"} {
		for _, limit := range []int64{0, -1, size - 1, size, size + 1} {
			t.Run(fmt.Sprintf("%s/limit=%d", failure, limit), func(t *testing.T) {
				var goodCalls, badCalls atomic.Int32
				good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					goodCalls.Add(1)
					got, err := io.ReadAll(r.Body)
					if err != nil || string(got) != payload {
						t.Errorf("good upstream body = %q, %v", got, err)
					}
					_, _ = w.Write(got)
				}))
				t.Cleanup(good.Close)
				bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					badCalls.Add(1)
					got, err := io.ReadAll(r.Body)
					if failure == "truncated" {
						if err == nil || !strings.HasPrefix(payload, string(got)) {
							t.Errorf("truncated request read error = %v", err)
						}
					} else if err != nil || string(got) != payload {
						t.Errorf("failing upstream body = %q, %v", got, err)
					}
					if failure == "response" {
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = w.Write([]byte("synthetic response canary"))
						return
					}
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
				}))
				t.Cleanup(bad.Close)
				h := minimalHandler(1,
					&Upstream{Host: new(Host), Dial: good.Listener.Addr().String()},
					&Upstream{Host: new(Host), Dial: bad.Listener.Addr().String()})
				h.RequestBuffers = limit
				h.ResponseBuffers = 4
				tr := &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						if failure == "dial" && addr == bad.Listener.Addr().String() {
							return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("forced local dial failure")}
						}
						return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
					},
					ResponseHeaderTimeout: 5 * time.Second,
				}
				h.Transport = testTransport{tr}
				t.Cleanup(tr.CloseIdleConnections)
				if failure == "response" {
					h.LoadBalancing.RetryMatch = []caddyhttp.MatcherSet{{
						newExpressionMatcher(t, "{http.reverse_proxy.status_code} == 503"),
					}}
				}
				req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", strings.NewReader(payload)))
				if failure == "truncated" {
					req.Body = io.NopCloser(io.MultiReader(strings.NewReader(payload), iotest.ErrReader(io.ErrUnexpectedEOF)))
					req.ContentLength++
				}
				defer req.Body.Close()
				rec := httptest.NewRecorder()
				err := h.ServeHTTP(rec, req, nil)
				wantRetry := failure != "truncated" && (failure == "dial" || limit < 0 || limit > size)
				if wantRetry {
					if err != nil || rec.Body.String() != payload || goodCalls.Load() != 1 {
						t.Fatalf("retry: body=%q good calls=%d err=%v", rec.Body.String(), goodCalls.Load(), err)
					}
				} else if err == nil || goodCalls.Load() != 0 {
					t.Fatalf("consumed stream retried: good calls=%d err=%v", goodCalls.Load(), err)
				}
				wantBad := int32(1)
				if failure == "dial" {
					wantBad = 0
				}
				// A body read error may abort the write before even the request
				// headers reach the local server.
				if got := badCalls.Load(); failure != "truncated" && got != wantBad {
					t.Fatalf("failing upstream calls = %d, want %d", got, wantBad)
				}
			})
		}
	}
}

func TestBufferedBodiesConcurrentCanaries(t *testing.T) {
	const workers = 16
	for round := range 8 {
		ready := make(chan *bodyReadCloser, workers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for worker := range workers {
			wg.Go(func() {
				payload := strings.Repeat(fmt.Sprintf("synthetic-%d-%d|", round, worker), 32)
				// Exercise the shared request/response pool after repeated closes
				// of a partially buffered body, while other leases remain active.
				old, _ := (Handler{}).bufferedBody(io.NopCloser(strings.NewReader(payload)), 4)
				old.Close()
				body, _ := (Handler{}).bufferedBody(io.NopCloser(strings.NewReader(payload)), int64(len(payload)+worker%3-1))
				defer body.Close()
				ready <- body.(*bodyReadCloser)
				<-start
				old.Close()
				got, err := io.ReadAll(body)
				if err != nil || string(got) != payload {
					t.Errorf("body changed: got %q, want %q, err=%v", got, payload, err)
				}
			})
		}
		leased := make(map[*bytes.Buffer]bool)
		for range workers {
			b := <-ready
			if leased[b.buf] {
				t.Error("concurrent bodies leased the same buffer")
			}
			leased[b.buf] = true
		}
		close(start)
		wg.Wait()
	}
}
