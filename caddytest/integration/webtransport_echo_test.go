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

package integration

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// This file provides a terminating WebTransport handler used exclusively
// as a test upstream for the WebTransport reverse-proxy integration
// tests in webtransport_test.go. Keeping it in a _test.go file (mirroring
// mockdns_test.go) means the http.handlers.webtransport module is only
// registered in the integration test binary — it does not ship in
// production Caddy builds.

func init() {
	caddy.RegisterModule(WebTransportEcho{})
}

// webtransportEchoProtocol is the :protocol pseudo-header value for an
// HTTP/3 Extended CONNECT that establishes a WebTransport session.
const webtransportEchoProtocol = "webtransport"

// webtransportEchoWriter is the naked HTTP/3 response-writer shape that
// webtransport.Server.Upgrade type-asserts on.
type webtransportEchoWriter interface {
	http.ResponseWriter
	http3.Settingser
	http3.HTTPStreamer
}

// WebTransportEcho terminates an incoming WebTransport session and echoes
// bytes on each accepted bidirectional stream. Registered as
// `http.handlers.webtransport` in the integration test binary.
type WebTransportEcho struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (WebTransportEcho) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.webtransport",
		New: func() caddy.Module { return new(WebTransportEcho) },
	}
}

// Provision sets up the handler.
func (h *WebTransportEcho) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	return nil
}

// ServeHTTP upgrades the request to a WebTransport session and echoes
// bytes on each accepted bidirectional stream. Non-WebTransport requests
// are passed through to the next handler.
func (h *WebTransportEcho) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !isWebTransportEchoUpgrade(r) {
		return next.ServeHTTP(w, r)
	}

	srv, ok := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok || srv == nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: caddyhttp.Server not in request context"))
	}
	wtServer, ok := srv.WebTransportServer().(*webtransport.Server)
	if !ok || wtServer == nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: HTTP/3 is not enabled on this server"))
	}

	naked, ok := caddyhttp.UnwrapResponseWriterAs[webtransportEchoWriter](w)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: underlying writer does not support WebTransport upgrade"))
	}

	session, err := wtServer.Upgrade(naked, r)
	if err != nil {
		h.logger.Debug("webtransport upgrade failed", zap.Error(err))
		return caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("webtransport upgrade: %w", err))
	}

	h.echoStreams(session)
	return nil
}

// echoStreams accepts bidirectional streams on session until the session
// ends, and echoes bytes on each one.
func (h *WebTransportEcho) echoStreams(session *webtransport.Session) {
	ctx := session.Context()
	for {
		str, err := session.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(s *webtransport.Stream) {
			// io.Copy from the stream back to itself echoes everything
			// received on this bidirectional stream. When the peer closes
			// its send side we observe EOF and close our send side too.
			if _, err := io.Copy(s, s); err != nil && h.logger != nil {
				h.logger.Debug("webtransport echo stream error", zap.Error(err))
			}
			_ = s.Close()
		}(str)
	}
}

// isWebTransportEchoUpgrade reports whether r is an HTTP/3 Extended
// CONNECT that requests a WebTransport session. The quic-go/http3 server
// places the :protocol pseudo-header value in r.Proto for CONNECT requests.
func isWebTransportEchoUpgrade(r *http.Request) bool {
	return r.ProtoMajor == 3 &&
		r.Method == http.MethodConnect &&
		r.Proto == webtransportEchoProtocol
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*WebTransportEcho)(nil)
	_ caddyhttp.MiddlewareHandler = (*WebTransportEcho)(nil)
)

// --- unit tests ------------------------------------------------------------

func TestIsWebTransportEchoUpgrade(t *testing.T) {
	cases := []struct {
		name  string
		proto string
		major int
		meth  string
		want  bool
	}{
		{"h3 connect webtransport", "webtransport", 3, http.MethodConnect, true},
		{"h3 connect websocket", "websocket", 3, http.MethodConnect, false},
		{"h2 connect webtransport", "webtransport", 2, http.MethodConnect, false},
		{"h3 GET", "HTTP/3.0", 3, http.MethodGet, false},
		{"h3 connect missing :protocol", "HTTP/3.0", 3, http.MethodConnect, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.meth, "/", nil)
			r.ProtoMajor = tc.major
			r.Proto = tc.proto
			if got := isWebTransportEchoUpgrade(r); got != tc.want {
				t.Errorf("isWebTransportEchoUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
}

// echoNextNoop is a stand-in for the next handler. It records whether it
// was invoked, used to assert that non-WebTransport requests pass through.
type echoNextNoop struct{ called bool }

func (n *echoNextNoop) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	n.called = true
	return nil
}

func TestWebTransportEcho_PassesThroughNonWebTransportRequests(t *testing.T) {
	h := &WebTransportEcho{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	nx := &echoNextNoop{}
	if err := h.ServeHTTP(w, r, nx); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if !nx.called {
		t.Error("expected next handler to be invoked for non-WebTransport request")
	}
}
