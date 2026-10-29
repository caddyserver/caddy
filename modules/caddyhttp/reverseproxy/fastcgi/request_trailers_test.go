package fastcgi

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestRequestTrailersFastCGI(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- fcgi.Serve(backend, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				http.Error(w, err.Error(), 500)
				return
			}
			// FastCGI carries a length and stdin bytes, not HTTP trailers.
			if len(r.Trailer) != 0 || len(r.TransferEncoding) != 0 {
				t.Errorf("unexpected HTTP framing: %v %v", r.Trailer, r.TransferEncoding)
			}
			w.Header().Set("X-Body-Length", fmt.Sprint(r.ContentLength))
			_, _ = w.Write(body)
		}))
	}()
	defer func() { backend.Close(); <-done }()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserve.Addr().String()
	reserve.Close()
	config, err := json.Marshal(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"test": map[string]any{
			"listen": []string{addr}, "automatic_https": map[string]any{"disable": true},
			"routes": []any{map[string]any{"handle": []any{map[string]any{
				"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": backend.Addr().String()}},
				"transport": map[string]any{"protocol": "fastcgi", "root": "/", "split_path": []string{".php"}},
			}}}},
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Omit request_buffers so provisioning applies FastCGI's default 4096-byte buffer.
	if err := caddy.Load(config, true); err != nil {
		t.Fatal(err)
	}
	defer caddy.Stop()
	client := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	for _, body := range []string{"", "hello", strings.Repeat("x", 4095)} {
		for _, trailers := range []bool{false, true} {
			t.Run(fmt.Sprintf("length=%d/trailers=%t", len(body), trailers), func(t *testing.T) {
				req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/index.php", io.NopCloser(strings.NewReader(body)))
				if err != nil {
					t.Fatal(err)
				}
				req.ContentLength = -1
				if trailers {
					req.Trailer = http.Header{"Content-Digest": {"digest"}}
				}
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil || res.StatusCode != 200 || string(got) != body || res.Header.Get("X-Body-Length") != fmt.Sprint(len(body)) {
					t.Fatalf("status=%d length=%q body bytes=%d (want %d), error=%v", res.StatusCode, res.Header.Get("X-Body-Length"), len(got), len(body), err)
				}
			})
		}
	}
}
