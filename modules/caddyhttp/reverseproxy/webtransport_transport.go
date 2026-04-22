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
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	caddywt "github.com/caddyserver/caddy/v2/modules/caddyhttp/webtransport"
)

// isWebTransportExtendedConnect reports whether r is an HTTP/3 Extended
// CONNECT that requests a WebTransport session. Does not check whether
// WebTransport proxying is configured; callers gate on Handler state.
func isWebTransportExtendedConnect(r *http.Request) bool {
	return r.ProtoMajor == 3 && r.Method == http.MethodConnect && r.Proto == caddywt.Protocol
}

// serveWebTransport handles a WebTransport Extended CONNECT: selects an
// upstream, upgrades the client-side session, dials the upstream-side
// session, and runs the session pump until both sides close.
//
// Unlike the regular HTTP proxy path, there are no retries: a failed
// dial closes the client's session and returns (so the handler chain
// can finish). Requests that reach this function are already known to
// be WebTransport; callers should gate with isWebTransportProxyRequest.
func (h *Handler) serveWebTransport(w http.ResponseWriter, r *http.Request) error {
	srv, ok := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok || srv == nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: no caddyhttp.Server in request context"))
	}
	wtServer, ok := srv.WebTransportServer().(*webtransport.Server)
	if !ok || wtServer == nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: HTTP/3 is not enabled on this server; WebTransport requires H3"))
	}

	// Select an upstream via the configured LB policy. No retries.
	upstreams := h.Upstreams
	if h.LoadBalancing == nil || h.LoadBalancing.SelectionPolicy == nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: load balancer is not configured"))
	}
	upstream := h.LoadBalancing.SelectionPolicy.Select(upstreams, r, w)
	if upstream == nil {
		return caddyhttp.Error(http.StatusBadGateway,
			errors.New("webtransport: no upstream available"))
	}

	// Reach the naked http3 response writer so Upgrade's type assertions
	// succeed through Caddy's wrapper chain.
	naked, ok := caddyhttp.UnwrapResponseWriterAs[caddywt.Writer](w)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: response writer does not support WebTransport upgrade"))
	}

	clientSess, err := wtServer.Upgrade(naked, r)
	if err != nil {
		h.logger.Debug("webtransport client upgrade failed", zap.Error(err))
		return caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("webtransport upgrade: %w", err))
	}

	ht := h.Transport.(*HTTPTransport)
	upstreamURL := buildWebTransportUpstreamURL(upstream.Dial, r)
	_, upstreamSess, err := dialUpstreamWebTransport(r.Context(), ht.h3Transport.TLSClientConfig, upstreamURL, r.Header.Clone())
	if err != nil {
		h.logger.Error("webtransport upstream dial failed",
			zap.String("upstream", upstreamURL),
			zap.Error(err))
		_ = clientSess.CloseWithError(0, "upstream dial failed")
		return nil
	}

	runWebTransportPump(clientSess, upstreamSess, h.logger)
	return nil
}

// buildWebTransportUpstreamURL constructs an https:// URL for the dialer
// using the upstream's Dial address (host:port) and the request's path
// + raw query. Scheme is fixed to https since WebTransport-over-H3
// requires TLS.
func buildWebTransportUpstreamURL(dial string, r *http.Request) string {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery != "" {
		return fmt.Sprintf("https://%s%s?%s", dial, path, r.URL.RawQuery)
	}
	return fmt.Sprintf("https://%s%s", dial, path)
}

// dialUpstreamWebTransport opens a WebTransport session to the upstream at
// urlStr (an https URL), forwarding reqHdr as headers on the Extended
// CONNECT request. The returned session is owned by the caller and must be
// closed when no longer in use. Return-value order matches
// webtransport.Dialer.Dial: (response, session, error).
//
// EXPERIMENTAL: this helper is an internal building block for the upcoming
// WebTransport reverse-proxy transport. Shape and behavior may change.
func dialUpstreamWebTransport(ctx context.Context, tlsCfg *tls.Config, urlStr string, reqHdr http.Header) (*http.Response, *webtransport.Session, error) {
	d := &webtransport.Dialer{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}
	return d.Dial(ctx, urlStr, reqHdr)
}
