package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type extendedConnectCapture struct {
	method              string
	headers             http.Header
	body                []byte
	extendedBodyPresent bool
	extendedConnectBody []byte
}

type extendedConnectCaptureTransport struct {
	mu      sync.Mutex
	capture extendedConnectCapture
}

func (tr *extendedConnectCaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	c := extendedConnectCapture{
		method:  req.Method,
		headers: req.Header.Clone(),
		body:    body,
	}
	if rc, ok := caddyhttp.GetVar(req.Context(), "extended_connect_websocket_body").(io.ReadCloser); ok {
		c.extendedBodyPresent = true
		c.extendedConnectBody, err = io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		_ = rc.Close()
	}

	tr.mu.Lock()
	tr.capture = c
	tr.mu.Unlock()

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

func (tr *extendedConnectCaptureTransport) Snapshot() extendedConnectCapture {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.capture
}

func TestServeHTTPRewritesExtendedConnectWebsocketRequest(t *testing.T) {
	tests := []struct {
		name       string
		protoMajor int
		proto      string
		headers    map[string]string
	}{
		{
			name:       "h2 extended connect",
			protoMajor: 2,
			proto:      "HTTP/2.0",
			headers: map[string]string{
				":protocol": "websocket",
			},
		},
		{
			name:       "h3 extended connect",
			protoMajor: 3,
			proto:      "websocket",
			headers:    map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const payload = "extended-connect-body"

			transport := new(extendedConnectCaptureTransport)
			h := &Handler{
				logger:    zap.NewNop(),
				Transport: transport,
				Upstreams: UpstreamPool{
					&Upstream{Host: new(Host), Dial: "127.0.0.1:8443"},
				},
				LoadBalancing: &LoadBalancing{
					SelectionPolicy: &RoundRobinSelection{},
				},
			}

			req := httptest.NewRequest(http.MethodConnect, "http://example.test/upgrade", strings.NewReader(payload))
			req.ProtoMajor = tc.protoMajor
			req.Proto = tc.proto
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
			req = prepareTestRequest(req)

			rr := httptest.NewRecorder()
			err := h.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))
			if err != nil {
				t.Fatalf("ServeHTTP() error = %v", err)
			}

			captured := transport.Snapshot()
			if captured.method != http.MethodGet {
				t.Fatalf("upstream method = %s, want %s", captured.method, http.MethodGet)
			}
			if got := captured.headers.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
				t.Fatalf("Upgrade header = %q, want websocket", got)
			}
			if got := captured.headers.Get("Connection"); !strings.EqualFold(got, "Upgrade") {
				t.Fatalf("Connection header = %q, want Upgrade", got)
			}
			if got := captured.headers.Get(":protocol"); got != "" {
				t.Fatalf(":protocol header should be removed, got %q", got)
			}
			if len(captured.body) != 0 {
				t.Fatalf("upstream request body length = %d, want 0", len(captured.body))
			}
			if !captured.extendedBodyPresent {
				t.Fatal("extended_connect_websocket_body variable missing from request context")
			}
			if string(captured.extendedConnectBody) != payload {
				t.Fatalf("extended_connect_websocket_body = %q, want %q", string(captured.extendedConnectBody), payload)
			}
		})
	}
}
