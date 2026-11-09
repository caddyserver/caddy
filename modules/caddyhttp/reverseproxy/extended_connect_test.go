package reverseproxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
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

func TestServeHTTPRewritesExtendedConnectWebsocketSecWebSocketKeyMatrix(t *testing.T) {
	const clientKey = "dGhlIHNhbXBsZSBub25jZQ=="

	protoCases := []struct {
		protoName  string
		protoMajor int
		proto      string
		headers    map[string]string
	}{
		{
			protoName:  "h2",
			protoMajor: 2,
			proto:      "HTTP/2.0",
			headers: map[string]string{
				":protocol": "websocket",
			},
		},
		{
			protoName:  "h3",
			protoMajor: 3,
			proto:      "websocket",
			headers:    map[string]string{},
		},
	}

	headerOpCases := []struct {
		opName       string
		userOps      *headers.HeaderOps
		transportOps *headers.HeaderOps
	}{
		{
			opName: "no header ops",
		},
		{
			opName: "user ops",
			userOps: &headers.HeaderOps{
				Set: http.Header{"X-User-Op": []string{"yes"}},
			},
		},
		{
			opName: "transport ops",
			transportOps: &headers.HeaderOps{
				Set: http.Header{"X-Transport-Op": []string{"yes"}},
			},
		},
		{
			opName: "both user and transport ops",
			userOps: &headers.HeaderOps{
				Set: http.Header{"X-User-Op": []string{"yes"}},
			},
			transportOps: &headers.HeaderOps{
				Set: http.Header{"X-Transport-Op": []string{"yes"}},
			},
		},
	}

	clientKeyCases := []struct {
		clientKeyName string
		sendClientKey bool
	}{
		{
			clientKeyName: "client sent key",
			sendClientKey: true,
		},
		{
			clientKeyName: "client without key",
			sendClientKey: false,
		},
	}

	for _, pc := range protoCases {
		for _, hoc := range headerOpCases {
			for _, ckc := range clientKeyCases {
				testName := pc.protoName + "/" + hoc.opName + "/" + ckc.clientKeyName
				t.Run(testName, func(t *testing.T) {
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
						transportHeaderOps: hoc.transportOps,
					}
					if hoc.userOps != nil {
						h.Headers = &headers.Handler{
							Request: hoc.userOps,
						}
					}

					req := httptest.NewRequest(http.MethodConnect, "http://example.test/upgrade", strings.NewReader("ws-data"))
					req.ProtoMajor = pc.protoMajor
					req.Proto = pc.proto
					for k, v := range pc.headers {
						req.Header.Set(k, v)
					}
					if ckc.sendClientKey {
						req.Header.Set("Sec-WebSocket-Key", clientKey)
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

					// Collect all Sec-WebSocket-Key values across canonical and non-canonical headers
					var keyValues []string
					for k, v := range captured.headers {
						if strings.EqualFold(k, "Sec-WebSocket-Key") {
							if k != "Sec-WebSocket-Key" {
								t.Fatalf("upstream WebSocket key spelling = %q, want Sec-WebSocket-Key", k)
							}
							keyValues = append(keyValues, v...)
						}
					}

					if len(keyValues) != 1 {
						t.Fatalf("expected exactly 1 Sec-WebSocket-Key value, got %d: %v (headers: %#v)",
							len(keyValues), keyValues, captured.headers)
					}

					upstreamKey := keyValues[0]
					if ckc.sendClientKey && upstreamKey == clientKey {
						t.Fatalf("upstream Sec-WebSocket-Key was not replaced by generated key; still got client key %q", clientKey)
					}

					decoded, err := base64.StdEncoding.DecodeString(upstreamKey)
					if err != nil {
						t.Fatalf("upstream Sec-WebSocket-Key %q is not valid base64: %v", upstreamKey, err)
					}
					if len(decoded) != 16 {
						t.Fatalf("upstream Sec-WebSocket-Key decoded length = %d, want 16 bytes", len(decoded))
					}

					if hoc.userOps != nil {
						if got := captured.headers.Get("X-User-Op"); got != "yes" {
							t.Fatalf("X-User-Op header = %q, want 'yes'", got)
						}
					}
					if hoc.transportOps != nil {
						if got := captured.headers.Get("X-Transport-Op"); got != "yes" {
							t.Fatalf("X-Transport-Op header = %q, want 'yes'", got)
						}
					}
				})
			}
		}
	}
}

func TestUpgradeResponseWebsocketHeaders(t *testing.T) {
	for _, proto := range []int{1, 2, 3} {
		t.Run("h"+strconv.Itoa(proto), func(t *testing.T) {
			h := &Handler{logger: zap.NewNop()}
			req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.test/upgrade", nil))
			req.ProtoMajor = proto
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			wantStatus := http.StatusSwitchingProtocols
			if proto > 1 {
				caddyhttp.SetVar(req.Context(), "extended_connect_websocket_body", http.NoBody)
				wantStatus = http.StatusOK
			}
			res := &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Header:     req.Header.Clone(),
				Body:       fakeRWC{strings.NewReader("")},
			}
			res.Header.Set("Sec-WebSocket-Accept", "backend-accept")
			res.Header.Set("Sec-WebSocket-Protocol", "chat")
			rw := upgradeHeaderRecorder{httptest.NewRecorder()}
			h.handleUpgradeResponse(h.logger, rw, req, res, "test-upstream")
			response := rw.Result()
			defer response.Body.Close()
			if response.StatusCode != wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode, wantStatus)
			}
			var accept, protocol string
			for key, values := range response.Header {
				if strings.EqualFold(key, "Sec-WebSocket-Accept") {
					if proto > 1 {
						t.Fatalf("extended CONNECT response contains %s", key)
					}
					if key != "Sec-WebSocket-Accept" {
						t.Fatalf("WebSocket accept spelling = %q, want Sec-WebSocket-Accept", key)
					}
					accept = strings.Join(values, ",")
				}
				if strings.EqualFold(key, "Sec-WebSocket-Protocol") {
					protocol = strings.Join(values, ",")
				}
			}
			if proto == 1 && accept != "backend-accept" {
				t.Fatalf("accept = %q, want backend-accept", accept)
			}
			if protocol != "chat" {
				t.Fatalf("subprotocol = %q, want chat", protocol)
			}
		})
	}
}

type upgradeHeaderRecorder struct{ *httptest.ResponseRecorder }

// Stop after the headers are committed, before the tunnel starts.
func (upgradeHeaderRecorder) FlushError() error { return io.ErrClosedPipe }
