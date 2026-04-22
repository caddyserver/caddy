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

// Package webtransport is an EXPERIMENTAL HTTP handler that terminates a
// WebTransport session (draft-ietf-webtrans-http3) on top of Caddy's HTTP/3
// server and echoes bytes on each bidirectional stream. It exists mainly as
// a test upstream for the WebTransport reverse-proxy transport. Behavior
// and configuration are subject to change without notice.
package webtransport

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Protocol is the :protocol pseudo-header value sent by a client that wants
// to establish a WebTransport session over HTTP/3 Extended CONNECT.
const Protocol = "webtransport"

// Writer is the interface satisfied by the naked HTTP/3 response writer.
// webtransport.Server.Upgrade performs these assertions itself; callers
// can use caddyhttp.UnwrapResponseWriterAs[Writer] to reach it past
// Caddy's ResponseWriter wrapping chain before calling Upgrade.
type Writer interface {
	http.ResponseWriter
	http3.Settingser
	http3.HTTPStreamer
}

// Handler terminates an incoming WebTransport session and echoes bytes on
// each bidirectional stream. EXPERIMENTAL: intended primarily as a test
// upstream for the WebTransport reverse-proxy transport.
type Handler struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.webtransport",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	return nil
}

// ServeHTTP upgrades the request to a WebTransport session and echoes bytes
// on each accepted bidirectional stream. Non-WebTransport requests are
// passed through to the next handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !isWebTransportUpgrade(r) {
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

	naked, ok := caddyhttp.UnwrapResponseWriterAs[Writer](w)
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
func (h *Handler) echoStreams(session *webtransport.Session) {
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

// isWebTransportUpgrade reports whether r is an HTTP/3 Extended CONNECT that
// requests a WebTransport session. The quic-go/http3 server places the
// :protocol pseudo-header value in r.Proto for CONNECT requests.
func isWebTransportUpgrade(r *http.Request) bool {
	return r.ProtoMajor == 3 &&
		r.Method == http.MethodConnect &&
		r.Proto == Protocol
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
