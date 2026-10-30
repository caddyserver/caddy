package reverseproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func testRequestBuffering(t *testing.T, memory, maxSize, maxDisk int64) *RequestBufferOptions {
	t.Helper()
	b := &RequestBufferOptions{MaxSize: maxSize, MaxDisk: maxDisk, TempDir: t.TempDir()}
	if err := b.provision(memory); err != nil {
		t.Fatal(err)
	}
	return b
}

func assertRequestBufferEmpty(t *testing.T, b *RequestBufferOptions) {
	t.Helper()
	files, err := os.ReadDir(b.TempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("temporary files remain: %v", files)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.diskUsage != 0 {
		t.Errorf("disk usage = %d, want 0", b.diskUsage)
	}
}

func TestRequestBufferingRoundTrip(t *testing.T) {
	for _, size := range []int{0, 7, 8, 9, 32768, 32769, 65536} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			b := testRequestBuffering(t, 8, 65536, 65536)
			want := strings.Repeat("x", size)
			original := newCloseOnCloseReader(want)
			body, err := b.buffer(context.Background(), original)
			if err != nil {
				t.Fatal(err)
			}
			defer body.Close()
			if !original.closed {
				t.Error("original body was not closed")
			}
			if body.size != int64(size) {
				t.Errorf("length = %d, want %d", body.size, size)
			}
			if (body.file != nil) != (size > 8) {
				t.Error("unexpected storage choice")
			}
			if body.file != nil {
				st, err := body.file.Stat()
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
					t.Errorf("temporary file permissions = %v", st.Mode())
				}
			}
			// Every attempt must receive the entire body, even after another reader
			// has consumed it. This also exercises the exact memory and disk limits.
			for range 2 {
				got, err := io.ReadAll(body.reader())
				if err != nil || string(got) != want {
					t.Fatalf("replay length = %d, err = %v", len(got), err)
				}
			}
			if err := body.Close(); err != nil {
				t.Fatal(err)
			}
			if err := body.Close(); err != nil {
				t.Fatal(err)
			}
			assertRequestBufferEmpty(t, b)
		})
	}
}

type failingUpload struct {
	io.Reader
	err error
}

func (r failingUpload) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		err = r.err
	}
	return n, err
}

func TestRequestBufferingFailureCleanup(t *testing.T) {
	readErr := errors.New("upload interrupted")
	for _, tc := range []struct {
		name     string
		makeBody func() io.ReadCloser
		maxSize  int64
		status   int
		cause    error
	}{
		{"size limit", func() io.ReadCloser { return io.NopCloser(strings.NewReader(strings.Repeat("x", 65))) }, 64, 413, nil},
		{"read failure", func() io.ReadCloser {
			return io.NopCloser(failingUpload{strings.NewReader(strings.Repeat("x", 33)), readErr})
		}, 64, 400, readErr},
		{"request_body limit", func() io.ReadCloser {
			return http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(strings.NewReader(strings.Repeat("x", 65))), 32)
		}, 64, 413, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := testRequestBuffering(t, 8, tc.maxSize, 64)
			_, err := b.buffer(context.Background(), tc.makeBody())
			var he caddyhttp.HandlerError
			if !errors.As(err, &he) || he.StatusCode != tc.status {
				t.Fatalf("error = %v, want HTTP %d", err, tc.status)
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Errorf("lost read error: %v", err)
			}
			assertRequestBufferEmpty(t, b)
		})
	}
}

func TestRequestBufferingDiskBudget(t *testing.T) {
	b := testRequestBuffering(t, 4, 64, 64)
	first, err := b.buffer(context.Background(), io.NopCloser(strings.NewReader(strings.Repeat("a", 33))))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, err = b.buffer(context.Background(), io.NopCloser(strings.NewReader(strings.Repeat("b", 32))))
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != 503 {
		t.Fatalf("error = %v, want HTTP 503", err)
	}
	files, err := os.ReadDir(b.TempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %d, want the first request's file only", len(files))
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	// A released budget can be fully reused; an EOF probe must not reserve more.
	second, err := b.buffer(context.Background(), io.NopCloser(strings.NewReader(strings.Repeat("c", 64))))
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	assertRequestBufferEmpty(t, b)
}

func TestRequestBufferingConcurrentBudget(t *testing.T) {
	b := testRequestBuffering(t, 1, 1024, 2048)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			body, err := b.buffer(context.Background(), io.NopCloser(strings.NewReader(strings.Repeat("x", 1024))))
			if err != nil {
				var he caddyhttp.HandlerError
				if !errors.As(err, &he) || he.StatusCode != 503 {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			b.mu.Lock()
			if b.diskUsage > b.MaxDisk {
				t.Errorf("budget exceeded: %d", b.diskUsage)
			}
			b.mu.Unlock()
			if err := body.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	assertRequestBufferEmpty(t, b)
}

func TestRequestBufferingCancellation(t *testing.T) {
	b := testRequestBuffering(t, 8, 64, 64)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	original := newCloseOnCloseReader("upload")
	_, err := b.buffer(ctx, original)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if !original.closed {
		t.Error("original body was not closed")
	}
	assertRequestBufferEmpty(t, b)
}

func TestRequestBufferingPrepareRequest(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			b := testRequestBuffering(t, 4, 64, 64)
			if !unknown {
				b.TempDir = filepath.Join(b.TempDir, "missing")
			}
			h := Handler{RequestBufferOptions: b, RequestBuffers: b.memory}
			req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("abcdefghij"))
			if unknown {
				req.ContentLength = -1
				req.Header.Del("Content-Length")
			}
			prepared, err := h.prepareRequest(prepareTestRequest(req), caddy.NewReplacer())
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Body.Close()
			if prepared.ContentLength != 10 {
				t.Errorf("ContentLength = %d", prepared.ContentLength)
			}
			if unknown && prepared.Header.Get("Content-Length") != "10" {
				t.Error("missing Content-Length header")
			}
			got, err := io.ReadAll(prepared.Body)
			if err != nil || string(got) != "abcdefghij" {
				t.Fatalf("body = %q, error = %v", got, err)
			}
			if _, spooled := prepared.Body.(*spooledBody); !unknown && spooled {
				t.Error("known-length body was disk-buffered")
			}
		})
	}
}

func TestRequestBufferingBeforeDialAndErrorStatus(t *testing.T) {
	b := testRequestBuffering(t, 4, 10, 64)
	h := minimalHandler(0, &Upstream{Host: new(Host), Dial: "127.0.0.1:12345"})
	h.RequestBufferOptions = b
	h.RequestBuffers = b.memory
	h.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("upstream called for rejected upload")
		return nil, errors.New("unexpected dial")
	})
	req := prepareTestRequest(httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("too many upload bytes")))
	req.ContentLength = -1
	err := h.ServeHTTP(httptest.NewRecorder(), req, nil)
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != 413 {
		t.Fatalf("error = %v, want HTTP 413", err)
	}
	assertRequestBufferEmpty(t, b)
}

func TestRequestBufferingRetry(t *testing.T) {
	for _, memory := range []int64{4, 64} {
		t.Run(fmt.Sprint(memory), func(t *testing.T) {
			b := testRequestBuffering(t, memory, 64, 64)
			h := minimalHandler(1, &Upstream{Host: new(Host), Dial: "127.0.0.1:12345"})
			h.RequestBufferOptions = b
			h.RequestBuffers = b.memory
			calls := 0
			h.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					_, err := io.ReadFull(req.Body, make([]byte, 3))
					if err != nil {
						t.Error(err)
					}
					_ = req.Body.Close()
					return nil, errors.New("upstream failed after reading part of body")
				}
				got, err := io.ReadAll(req.Body)
				if err != nil || string(got) != "abcdefghij" {
					t.Errorf("replayed body = %q, error = %v", got, err)
				}
				if req.ContentLength != 10 || req.Header.Get("Content-Length") != "10" {
					t.Error("wrong framing")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2}, nil
			})
			req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", newCloseOnCloseReader("abcdefghij")))
			req.ContentLength = -1
			rec := httptest.NewRecorder()
			if err := h.ServeHTTP(rec, req, nil); err != nil {
				t.Fatal(err)
			}
			if calls != 2 || rec.Body.String() != "ok" {
				t.Errorf("calls = %d, response = %q", calls, rec.Body.String())
			}
			assertRequestBufferEmpty(t, b)
		})
	}
}

func TestRequestBufferingCaddyfile(t *testing.T) {
	for _, tc := range []struct {
		name, input       string
		wantErr, wantDisk bool
	}{
		{"legacy memory", "request_buffers 16KiB", false, false},
		{"legacy unlimited", "request_buffers unlimited", false, false},
		{"legacy zero", "request_buffers 0", false, false},
		{"empty block", "request_buffers 16KiB {\n}", false, true},
		{"options", "request_buffers 16KiB {\n max_size 1MiB\n max_disk 2MiB\n temp_dir /tmp/uploads\n}", false, true},
		{"old directive", "request_buffering", true, false},
		{"missing size", "request_buffers {\n max_size 1MiB\n}", true, false},
		{"unlimited with disk", "request_buffers unlimited {\n}", true, false},
		{"zero with disk", "request_buffers 0 {\n}", true, false},
		{"extra argument", "request_buffers 16KiB unexpected", true, false},
		{"unknown option", "request_buffers 16KiB {\n unknown 1KiB\n}", true, false},
		{"duplicate memory setting", "request_buffers 16KiB {\n memory 1KiB\n}", true, false},
		{"zero size", "request_buffers 16KiB {\n max_size 0\n}", true, false},
		{"memory overflow", "request_buffers 18446744073709551615", true, false},
		{"option overflow", "request_buffers 16KiB {\n max_disk 18446744073709551615\n}", true, false},
		{"extra option argument", "request_buffers 16KiB {\n max_disk 1KiB 2KiB\n}", true, false},
		{"duplicate block", "request_buffers 16KiB {\n}\n request_buffers 16KiB {\n}", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h Handler
			input := "reverse_proxy localhost:9000 {\n" + tc.input + "\n response_buffers 32KiB\n}"
			err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if (h.RequestBufferOptions != nil) != tc.wantDisk {
				t.Fatalf("disk buffering enabled = %v, want %v", h.RequestBufferOptions != nil, tc.wantDisk)
			}
			if h.ResponseBuffers != 32768 {
				t.Error("optional block consumed following directive")
			}
			if tc.name == "options" && (h.RequestBuffers != 16384 || h.RequestBufferOptions.MaxSize != 1048576 || h.RequestBufferOptions.MaxDisk != 2097152 || h.RequestBufferOptions.TempDir != "/tmp/uploads") {
				t.Errorf("wrong options: %+v", h.RequestBufferOptions)
			}
		})
	}
}

func TestRequestBufferingSpillMemoryPrefix(t *testing.T) {
	b := testRequestBuffering(t, 8, 64, 64)
	want := "abcdefghij"
	body, err := b.buffer(context.Background(), io.NopCloser(iotest.OneByteReader(strings.NewReader(want))))
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	if err != nil || string(got) != want {
		t.Fatalf("spilled body = %q, error = %v", got, err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	assertRequestBufferEmpty(t, b)
}

func TestRequestBufferingIncremental(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(fmt.Sprint(known), func(t *testing.T) {
			b := testRequestBuffering(t, 4, 64, 64)
			h := incrementalHandler("127.0.0.1:12345")
			h.RequestBufferOptions = b
			h.RequestBuffers = b.memory
			called := false
			h.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				called = true
				_, _ = io.Copy(io.Discard, req.Body)
				return &http.Response{StatusCode: 204, Header: make(http.Header), Body: http.NoBody}, nil
			})
			rec := httptest.NewRecorder()
			err := h.ServeHTTP(rec, incrementalRequest("hello", known), nil)
			assertRefused(t, err, rec.Header())
			if called {
				t.Error("incremental request was forwarded with an explicit buffer")
			}
			assertRequestBufferEmpty(t, b)
		})
	}
}

func TestRequestBufferingInvalidConfig(t *testing.T) {
	for _, b := range []*RequestBufferOptions{{MaxSize: -1}, {MaxDisk: -1}} {
		if err := b.provision(4096); err == nil {
			t.Errorf("accepted negative limit: %+v", b)
		}
	}
	for _, size := range []int64{-1, 0} {
		h := Handler{RequestBufferOptions: new(RequestBufferOptions), RequestBuffers: size}
		if err := h.Provision(caddy.Context{}); err == nil || !strings.Contains(err.Error(), "positive, finite request_buffers") {
			t.Fatalf("invalid memory threshold %d: %v", size, err)
		}
	}
}

func TestRequestBufferingJSONCompatibility(t *testing.T) {
	for _, raw := range []string{
		`{"request_buffers":16384}`,
		`{"request_buffers":-1}`,
		`{"request_buffers":16384,"request_buffer_options":{"max_size":1048576,"max_disk":2097152}}`,
	} {
		var h Handler
		if err := json.Unmarshal([]byte(raw), &h); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatal(err)
		}
		var size int64
		if err := json.Unmarshal(got["request_buffers"], &size); err != nil {
			t.Fatal(err)
		}
		if size != h.RequestBuffers {
			t.Error("request_buffers did not retain its numeric representation")
		}
		if h.RequestBufferOptions != nil {
			if err := h.RequestBufferOptions.provision(h.RequestBuffers); err != nil {
				t.Fatal(err)
			}
			if h.RequestBufferOptions.memory != size {
				t.Error("disk buffering uses a different memory threshold")
			}
		}
	}
}

func TestRequestBufferingDiskFailure(t *testing.T) {
	b := testRequestBuffering(t, 4, 64, 64)
	b.TempDir = filepath.Join(b.TempDir, "missing")
	h := minimalHandler(0, &Upstream{Host: new(Host), Dial: "127.0.0.1:12345"})
	h.RequestBufferOptions = b
	h.RequestBuffers = b.memory
	h.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("upstream called after disk failure")
		return nil, errors.New("unexpected dial")
	})
	req := prepareTestRequest(httptest.NewRequest(http.MethodPost, "http://example.com/", newCloseOnCloseReader("abcdefghij")))
	req.ContentLength = -1
	err := h.ServeHTTP(httptest.NewRecorder(), req, nil)
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != 500 {
		t.Fatalf("error = %v, want HTTP 500", err)
	}
	if b.diskUsage != 0 {
		t.Errorf("quota leaked: %d", b.diskUsage)
	}
}

// Disk charges must survive an unsuccessful deletion, so later requests
// cannot silently consume storage that is still occupied by the leaked file.
func TestRequestBufferingCleanupFailure(t *testing.T) {
	b := testRequestBuffering(t, 4, 64, 64)
	body, err := b.buffer(context.Background(), io.NopCloser(strings.NewReader("abcdefghij")))
	if err != nil {
		t.Fatal(err)
	}
	name := body.file.Name()
	if err := body.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(name, "occupied"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err == nil {
		t.Fatal("expected cleanup error")
	}
	if b.diskUsage != 10 {
		t.Errorf("failed removal released quota: %d", b.diskUsage)
	}
}
