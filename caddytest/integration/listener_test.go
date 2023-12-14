package integration

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func setupListenerWrapperTest(t *testing.T, handlerFunc http.HandlerFunc) *caddytest.Tester {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", handlerFunc)
	srv := &http.Server{
		Handler: mux,
	}
	go srv.Serve(l)
	t.Cleanup(func() {
		_ = srv.Close()
		_ = l.Close()
	})
	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		local_certs
		servers :9443 {
			listener_wrappers {
				http_redirect
				tls
			}
		}
	}
	localhost {
		reverse_proxy %s
	}
  `, l.Addr().String()), "caddyfile")
	return tester
}

func TestHTTPRedirectWrapperWithLargeUpload(t *testing.T) {
	const uploadSize = (1024 * 1024) + 1 // 1 MB + 1 byte
	// 1 more than an MB
	body := make([]byte, uploadSize)
	rand.New(rand.NewSource(0)).Read(body)

	tester := setupListenerWrapperTest(t, func(writer http.ResponseWriter, request *http.Request) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(request.Body)
		if err != nil {
			t.Fatalf("failed to read body: %s", err)
		}

		if !bytes.Equal(buf.Bytes(), body) {
			t.Fatalf("body not the same")
		}

		writer.WriteHeader(http.StatusNoContent)
	})
	resp, err := tester.Client.Post("https://localhost:9443", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to post: %s", err)
	}

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %d != %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestLargeHttpRequest(t *testing.T) {
	tester := setupListenerWrapperTest(t, func(writer http.ResponseWriter, request *http.Request) {
		t.Fatal("not supposed to handle a request")
	})

	// We never read the body in any way, set an extra long header instead.
	req, _ := http.NewRequest("POST", "http://localhost:9443", nil)
	req.Header.Set("Long-Header", strings.Repeat("X", 1024*1024))
	_, err := tester.Client.Do(req)
	if err == nil {
		t.Fatal("not supposed to succeed")
	}
}
