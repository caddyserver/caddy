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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// trailerTestBody models net/http populating the original request's trailers
// during Read, including readers which return final bytes together with EOF.
type trailerTestBody struct {
	io.Reader
	finish func()
	err    error
	closed bool
}

func (b *trailerTestBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, errors.New("body closed")
	}
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		if b.finish != nil {
			b.finish()
			b.finish = nil
		}
		if b.err != nil {
			err = b.err
		}
	}
	return n, err
}

func (b *trailerTestBody) Close() error { b.closed = true; return nil }

type finalBytesReader struct{ *strings.Reader }

func (r finalBytesReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

func TestRequestTrailersEOF(t *testing.T) {
	for _, limit := range []int64{0, 2, 32, -1} {
		for _, declared := range []bool{false, true} {
			for _, finalBytes := range []bool{false, true} {
				t.Run(fmt.Sprintf("buffer=%d/declared=%t/final-bytes=%t", limit, declared, finalBytes), func(t *testing.T) {
					req := prepareTestRequest(httptest.NewRequest(http.MethodPut, "http://example.com/", nil))
					req.ContentLength = -1
					req.ProtoMajor = 2
					if declared {
						req.Trailer = http.Header{"Content-Digest": nil, "X-Checksum": nil, "X-Absent": nil}
					}
					want := http.Header{"Content-Digest": {"digest-one", "digest-two"}, "X-Checksum": {"checksum"}}
					if declared {
						want["X-Absent"] = nil
					}
					var reader io.Reader = strings.NewReader("hello")
					if finalBytes {
						reader = finalBytesReader{strings.NewReader("hello")}
					}
					body := &trailerTestBody{Reader: reader, finish: func() { req.Trailer = want.Clone() }}
					req.Body = body
					h := Handler{RequestBuffers: limit}
					out, err := h.prepareRequest(req, caddy.NewReplacer())
					if err != nil {
						t.Fatal(err)
					}
					defer out.Body.Close()
					if limit == 0 && body.finish == nil {
						t.Fatal("prepareRequest consumed streaming body")
					}
					got, err := io.ReadAll(out.Body)
					if err != nil || string(got) != "hello" {
						t.Fatalf("body=%q err=%v", got, err)
					}
					for range 2 {
						n, err := out.Body.Read(make([]byte, 8))
						if n != 0 || err != io.EOF {
							t.Fatalf("repeated read: n=%d err=%v", n, err)
						}
					}
					if !reflect.DeepEqual(out.Trailer, want) {
						t.Fatalf("trailers=%v, want %v", out.Trailer, want)
					}
					out.Trailer["Content-Digest"][0] = "outbound change"
					out.Trailer.Set("X-New", "outbound only")
					if !reflect.DeepEqual(req.Trailer, want) {
						t.Fatalf("outbound changes mutated incoming trailers: %v", req.Trailer)
					}
				})
			}
		}
	}
}

func TestRequestTrailersReadError(t *testing.T) {
	for _, readErr := range []error{io.ErrUnexpectedEOF, context.Canceled} {
		for _, limit := range []int64{0, 2, 32, -1} {
			t.Run(fmt.Sprintf("%v/buffer=%d", readErr, limit), func(t *testing.T) {
				req := prepareTestRequest(httptest.NewRequest(http.MethodPut, "http://example.com/", nil))
				req.ContentLength = -1
				req.Trailer = http.Header{"Content-Digest": nil}
				req.Body = &trailerTestBody{Reader: strings.NewReader("partial"), err: readErr, finish: func() {
					req.Trailer.Set("Content-Digest", "must not forward without EOF")
				}}
				out, err := (Handler{RequestBuffers: limit}).prepareRequest(req, caddy.NewReplacer())
				if err != nil {
					t.Fatal(err)
				}
				defer out.Body.Close()
				_, err = io.ReadAll(out.Body)
				// Unlimited buffering currently discards read errors; do not change
				// that existing policy here. It must still not publish trailers.
				if limit >= 0 && !errors.Is(err, readErr) {
					t.Fatalf("read error=%v, want %v", err, readErr)
				}
				if len(out.Trailer.Values("Content-Digest")) != 0 {
					t.Fatalf("published trailers after failed read: %v", out.Trailer)
				}
			})
		}
	}
}

type trailerObservation struct {
	Body    string
	Trailer http.Header
	Header  string
	Proto   string
}

func TestRequestTrailersNetwork(t *testing.T) {
	for _, network := range []string{"tcp", "unix"} {
		t.Run(network, func(t *testing.T) {
			if network == "unix" && runtime.GOOS == "windows" {
				t.Skip("Unix sockets are not supported by this test on Windows")
			}
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				_ = json.NewEncoder(w).Encode(trailerObservation{string(body), r.Trailer, r.Header.Get("X-Control"), r.Proto})
			}))
			dial := backend.Listener.Addr().String()
			if network == "unix" {
				_ = backend.Listener.Close()
				// Keep the socket path below the platform's sockaddr_un limit.
				dir, err := os.MkdirTemp("", "caddy-trailers-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir)
				backend.Listener, err = net.Listen("unix", filepath.Join(dir, "upstream.sock"))
				if err != nil {
					t.Fatal(err)
				}
				dial = "unix/" + backend.Listener.Addr().String()
			}
			backend.Start()
			defer backend.Close()
			for _, limit := range []int64{0, 2, 1 << 20, -1} {
				t.Run(fmt.Sprintf("buffer=%d", limit), func(t *testing.T) {
					ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
					defer cancel()
					transport := &HTTPTransport{}
					var err error
					transport.Transport, err = transport.NewTransport(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer transport.Transport.CloseIdleConnections()
					h := minimalHandler(0, &Upstream{Host: new(Host), Dial: dial})
					h.Transport = transport
					h.RequestBuffers = limit
					front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("X-Client-Protocol", r.Proto)
						if r.ProtoMajor == 1 && len(r.TransferEncoding) != 1 {
							t.Errorf("HTTP/1 request is not chunked: %v", r.TransferEncoding)
						}
						if err := h.ServeHTTP(w, prepareTestRequest(r), nil); err != nil {
							http.Error(w, err.Error(), 502)
						}
					}))
					front.EnableHTTP2 = true
					front.StartTLS()
					defer front.Close()
					for _, proto := range []int{1, 2} {
						tr := front.Client().Transport.(*http.Transport).Clone()
						tr.ForceAttemptHTTP2 = proto == 2
						tr.Protocols = new(http.Protocols)
						tr.Protocols.SetHTTP1(proto == 1)
						tr.Protocols.SetHTTP2(proto == 2)
						tr.TLSClientConfig.NextProtos = nil
						client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
						defer tr.CloseIdleConnections()
						for _, body := range []string{"", "hello, trailers"} {
							for _, trailers := range []http.Header{
								nil,
								{"Content-Digest": {"first", "second"}, "X-Checksum": {"checksum"}, "X-Absent": nil},
							} {
								req, err := http.NewRequest(http.MethodPut, front.URL, io.NopCloser(strings.NewReader(body)))
								if err != nil {
									t.Fatal(err)
								}
								req.ContentLength = -1
								req.Trailer = trailers.Clone()
								req.Header.Set("X-Control", "ordinary header")
								res, err := client.Do(req)
								if err != nil {
									t.Fatal(err)
								}
								var got trailerObservation
								err = json.NewDecoder(res.Body).Decode(&got)
								_ = res.Body.Close()
								if err != nil {
									t.Fatalf("decode status=%d: %v", res.StatusCode, err)
								}
								wantProto := fmt.Sprintf("HTTP/%d.%d", proto, 1)
								if proto == 2 {
									wantProto = "HTTP/2.0"
								}
								if res.Proto != wantProto || res.Header.Get("X-Client-Protocol") != wantProto {
									t.Fatalf("negotiated protocol: response=%s request=%s want=%s", res.Proto, res.Header.Get("X-Client-Protocol"), wantProto)
								}
								if res.StatusCode != 200 || got.Body != body || got.Header != "ordinary header" || got.Proto != "HTTP/1.1" {
									t.Fatalf("status=%d observation=%+v", res.StatusCode, got)
								}
								// An announced but absent field can be represented as nil
								// or one empty value by the HTTP/1 transport.
								if len(trailers) == 0 {
									if len(got.Trailer) != 0 {
										t.Fatalf("invented trailers: %v", got.Trailer)
									}
								} else {
									want := trailers.Clone()
									delete(want, "X-Absent")
									if got.Trailer.Get("X-Absent") != "" {
										t.Fatalf("absent trailer has value: %v", got.Trailer)
									}
									delete(got.Trailer, "X-Absent")
									if !reflect.DeepEqual(got.Trailer, want) {
										t.Fatalf("protocol=%s body=%q trailers=%v want=%v", wantProto, body, got.Trailer, want)
									}
								}
							}
						}
					}
				})
			}
		})
	}
}

// trailerRoundTripper makes retry failures deterministic without relying on
// racing the operating system to reserve an unused port.
type trailerRoundTripper func(*http.Request) (*http.Response, error)

func (f trailerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRequestTrailersRetry(t *testing.T) {
	for _, tc := range []struct {
		name        string
		limit       int64
		dialFailure bool
		partial     bool
	}{
		{name: "dial failure", dialFailure: true},
		{name: "dial failure with partial buffering", limit: 2, dialFailure: true},
		{name: "fully buffered replay", limit: 32},
		{name: "unlimited buffered replay", limit: -1},
		{name: "consumed stream cannot replay", partial: true},
		{name: "partially buffered stream cannot replay", limit: 2, partial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const payload = "hello, retry trailers"
			want := http.Header{"Content-Digest": {"first", "second"}, "X-Checksum": {"checksum"}}
			observed := make(chan trailerObservation, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				observed <- trailerObservation{Body: string(body), Trailer: r.Trailer}
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()
			h := minimalHandler(1, &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()})
			h.RequestBuffers = tc.limit
			transport := testTransport{&http.Transport{}}
			defer transport.CloseIdleConnections()
			attempts := 0
			h.Transport = trailerRoundTripper(func(r *http.Request) (*http.Response, error) {
				attempts++
				if attempts == 1 {
					if !tc.dialFailure {
						if tc.partial {
							if _, err := io.ReadFull(r.Body, make([]byte, 3)); err != nil {
								t.Errorf("initial partial read: %v", err)
							}
						} else {
							got, err := io.ReadAll(r.Body)
							if err != nil || string(got) != payload || !reflect.DeepEqual(r.Trailer, want) {
								t.Errorf("initial attempt: body=%q trailers=%v err=%v", got, r.Trailer, err)
							}
						}
					}
					_ = r.Body.Close()
					err := errors.New("controlled first-attempt failure")
					if tc.dialFailure {
						return nil, DialError{err}
					}
					return nil, err
				}
				if tc.partial {
					_, err := io.ReadAll(r.Body)
					if err == nil {
						t.Error("partially consumed request body became replayable")
					}
					return nil, errors.New("consumed body is not replayable")
				}
				return transport.RoundTrip(r)
			})
			req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
			req.ContentLength = -1
			req.Trailer = http.Header{"Content-Digest": nil, "X-Checksum": nil}
			req.Body = &trailerTestBody{Reader: strings.NewReader(payload), finish: func() { req.Trailer = want.Clone() }}
			defer req.Body.Close()
			ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()
			err := h.ServeHTTP(rec, req, nil)
			if attempts != 2 {
				t.Fatalf("attempts=%d, want 2", attempts)
			}
			if tc.partial {
				if err == nil {
					t.Fatal("partially consumed body was accepted for replay")
				}
				select {
				case got := <-observed:
					t.Fatalf("unexpected successful request: %+v", got)
				default:
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-observed:
				if got.Body != payload || !reflect.DeepEqual(got.Trailer, want) {
					t.Fatalf("replay=%+v, want body=%q trailers=%v", got, payload, want)
				}
			default:
				t.Fatal("upstream did not receive the replay")
			}
		})
	}
}

func TestRequestTrailersStreaming(t *testing.T) {
	for _, limit := range []int64{0, 2} {
		t.Run(fmt.Sprintf("buffer=%d", limit), func(t *testing.T) {
			prefixRead := make(chan struct{})
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				prefix := make([]byte, 5)
				if _, err := io.ReadFull(r.Body, prefix); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				close(prefixRead)
				rest, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				_ = json.NewEncoder(w).Encode(trailerObservation{Body: string(prefix) + string(rest), Trailer: r.Trailer})
			}))
			defer backend.Close()
			h := minimalHandler(0, &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()})
			defer h.Transport.(testTransport).CloseIdleConnections()
			h.RequestBuffers = limit
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := h.ServeHTTP(w, prepareTestRequest(r), nil); err != nil {
					http.Error(w, err.Error(), 502)
				}
			}))
			defer front.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			writeDone := make(chan error, 1)
			go func() {
				_, err := io.WriteString(writer, "hello")
				if err == nil {
					select {
					case <-prefixRead:
						_, err = io.WriteString(writer, ", streamed")
					case <-ctx.Done():
						err = ctx.Err()
					}
				}
				_ = writer.CloseWithError(err)
				writeDone <- err
			}()
			req, err := http.NewRequestWithContext(ctx, http.MethodPut, front.URL, reader)
			if err != nil {
				t.Fatal(err)
			}
			req.Trailer = http.Header{"Content-Digest": {"stream digest"}}
			client := front.Client()
			client.Timeout = 5 * time.Second
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var got trailerObservation
			if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Body != "hello, streamed" || !reflect.DeepEqual(got.Trailer, req.Trailer) {
				t.Fatalf("streamed request=%+v", got)
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// trailerCloseTracker lets tests wait for transport cleanup, including its
// background request writer, without polling goroutine counts.
type trailerCloseTracker struct {
	io.ReadCloser
	once     sync.Once
	readOnce sync.Once
	closed   chan struct{}
	readDone chan struct{}
}

func (b *trailerCloseTracker) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.readOnce.Do(func() { close(b.readDone) })
	}
	return n, err
}

func (b *trailerCloseTracker) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { close(b.closed) })
	return err
}

func TestRequestTrailersEarlyResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// Ensure the upload has started, then respond while the rest is blocked.
		if _, err := io.ReadFull(r.Body, make([]byte, 1)); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = http.NewResponseController(w).Flush()
	}))
	defer backend.Close()
	h := minimalHandler(0, &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()})
	defer h.Transport.(testTransport).CloseIdleConnections()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req := prepareTestRequest(httptest.NewRequest(http.MethodPut, "http://example.com/", reader))
	body := &trailerCloseTracker{ReadCloser: reader, closed: make(chan struct{}), readDone: make(chan struct{})}
	req.Body = body
	req.ContentLength = -1
	req.Trailer = http.Header{"Content-Digest": nil}
	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, "x")
		writeDone <- err
	}()
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, nil); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	// The HTTP server owns the incoming body and closes it after the
	// proxy returns. Model that ownership here; the transport may still be
	// reading the unfinished upload when an early response arrives.
	_ = req.Body.Close()
	select {
	case <-body.readDone:
	case <-ctx.Done():
		t.Fatal("interrupted upload read did not stop")
	}
	if req.Trailer.Get("Content-Digest") != "" {
		t.Fatal("early response invented trailers")
	}
}

func TestRequestTrailersCancellation(t *testing.T) {
	started := make(chan struct{})
	backendDone := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(backendDone)
		if _, err := io.ReadFull(r.Body, make([]byte, 1)); err != nil {
			return
		}
		close(started)
		_, err := io.Copy(io.Discard, r.Body)
		if err == nil {
			t.Error("canceled upstream body unexpectedly reached EOF")
		}
		if r.Trailer.Get("Content-Digest") != "" {
			t.Error("cancellation published trailer values")
		}
	}))
	defer backend.Close()
	h := minimalHandler(0, &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()})
	defer h.Transport.(testTransport).CloseIdleConnections()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	body := &trailerCloseTracker{ReadCloser: reader, closed: make(chan struct{}), readDone: make(chan struct{})}
	req := prepareTestRequest(httptest.NewRequest(http.MethodPut, "http://example.com/", body))
	req.ContentLength = -1
	req.Trailer = http.Header{"Content-Digest": nil}
	timeout, stop := context.WithTimeout(req.Context(), 5*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(timeout)
	defer cancel()
	req = req.WithContext(ctx)
	writeDone := make(chan error, 1)
	go func() { _, err := io.WriteString(writer, "x"); writeDone <- err }()
	rec := httptest.NewRecorder()
	done := make(chan error, 1)
	go func() { done <- h.ServeHTTP(rec, req, nil) }()
	select {
	case <-started:
	case <-timeout.Done():
		t.Fatal("upstream never received upload prefix")
	}
	cancel()
	// A real client disconnect also breaks the incoming socket read. Canceling
	// only a synthetic request context cannot unblock an unrelated io.Pipe.
	_ = writer.CloseWithError(context.Canceled)
	select {
	case err := <-done:
		if err != nil || rec.Code != 499 {
			t.Fatalf("cancellation: status=%d error=%v", rec.Code, err)
		}
	case <-timeout.Done():
		t.Fatal("proxy did not stop after cancellation")
	}
	for _, ch := range []<-chan struct{}{body.closed, body.readDone, backendDone} {
		select {
		case <-ch:
		case <-timeout.Done():
			t.Fatal("upload cleanup did not complete")
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}
