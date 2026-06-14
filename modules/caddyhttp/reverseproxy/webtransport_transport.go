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
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// webtransportProtocol is the :protocol pseudo-header value sent by a
// client that wants to establish a WebTransport session over an HTTP/3
// Extended CONNECT.
const webtransportProtocol = "webtransport"

// webtransportWriter is the naked HTTP/3 response-writer shape that
// webtransport.Server.Upgrade type-asserts on. Caddy's
// UnwrapResponseWriterAs walks the ResponseWriter wrapper chain to this
// type before calling Upgrade.
type webtransportWriter interface {
	http.ResponseWriter
	http3.Settingser
	http3.HTTPStreamer
}

// isWebTransportExtendedConnect reports whether r is an HTTP/3 Extended
// CONNECT that requests a WebTransport session. Does not check whether
// WebTransport proxying is configured; callers gate on Handler state.
func isWebTransportExtendedConnect(r *http.Request) bool {
	return r.ProtoMajor == 3 && r.Method == http.MethodConnect && r.Proto == webtransportProtocol
}

// webTransportTransport is implemented by reverse-proxy transports that
// can carry a WebTransport upstream dial. The handler type-asserts on
// this interface (rather than a concrete *HTTPTransport) so a future
// transport gaining HTTP/3 support can opt in. A nil return means the
// transport is configured but HTTP/3 is not enabled on it.
type webTransportTransport interface {
	webTransportTLSConfig() *tls.Config
}

// webTransportTLSConfig satisfies the webTransportTransport capability
// interface. Returns the HTTP/3 TLS config when HTTP/3 is enabled on
// this transport, or nil otherwise (signaling that this transport
// cannot dial WebTransport).
//
// EXPERIMENTAL: shape may change with the WebTransport feature.
func (h *HTTPTransport) webTransportTLSConfig() *tls.Config {
	if h.h3Transport == nil {
		return nil
	}
	return h.h3Transport.TLSClientConfig
}

// webTransportHijack runs inside reverseProxy in place of RoundTrip when
// the request is a WebTransport Extended CONNECT. The outer proxy loop
// has already resolved the upstream set, selected an upstream, filled
// DialInfo, published reverse_proxy.upstream.* placeholders, applied
// transport and user request-header ops, cloned the request, directed
// the request URL at the upstream, and bumped in-flight counters — so
// this function only does WT-specific plumbing: upstream WT dial,
// client upgrade, and session pumping.
//
// Error semantics match the outer loop's retry contract:
//   - Pre-dial misconfiguration (WT not enabled on the server, writer
//     stack unsupported, handler transport is not HTTP/3) returns
//     terminalError — no upstream can fix these conditions.
//   - Upstream dial failure returns DialError — safe to retry across
//     upstreams because no client-visible bytes have been written.
//   - Post-upgrade failures return terminalError because the 200 OK
//     has been flushed and the stream is hijacked.
//
// Requests that reach this function are already known to be WebTransport;
// callers should gate with isWebTransportExtendedConnect.
func (h *Handler) webTransportHijack(rw http.ResponseWriter, req *http.Request, repl *caddy.Replacer, di DialInfo, server *caddyhttp.Server) error {
	wtServer, ok := server.WebTransportServer().(*webtransport.Server)
	if !ok || wtServer == nil {
		return terminalError{caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: server has enable_webtransport=false or HTTP/3 is not enabled"))}
	}

	// Reach the naked http3 response writer so Upgrade's type assertions
	// succeed through Caddy's wrapper chain. Done before dialing so we
	// fail fast if the writer stack is unexpectedly incompatible.
	naked, ok := caddyhttp.UnwrapResponseWriterAs[webtransportWriter](rw)
	if !ok {
		return terminalError{caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: response writer does not support WebTransport upgrade"))}
	}

	// A WT CONNECT reached this handler because the parent server has
	// enable_webtransport=true. But the handler's transport still has to
	// speak HTTP/3 to dial the WT upstream.
	wtt, ok := h.Transport.(webTransportTransport)
	if !ok {
		return terminalError{caddyhttp.Error(http.StatusBadGateway,
			errors.New("webtransport: requires a WebTransport-capable transport (the 'http' transport with versions [\"3\"])"))}
	}
	tlsCfg := wtt.webTransportTLSConfig()
	if tlsCfg == nil {
		return terminalError{caddyhttp.Error(http.StatusBadGateway,
			errors.New("webtransport: transport does not include HTTP/3; set versions to [\"3\"]"))}
	}

	// Expand SNI placeholders (e.g. tls_server_name {http.request.host}) per
	// session. The normal HTTP/3 path does this via a custom h3Transport.Dial
	// hook (#7737); the WebTransport path dials through its own Dialer and
	// bypasses that hook, so expand here. Clone first — the transport's TLS
	// config is shared across sessions and must not be mutated in place.
	if strings.Contains(tlsCfg.ServerName, "{") {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = repl.ReplaceAll(tlsCfg.ServerName, "")
	}

	// Dial the upstream BEFORE upgrading the client. If the upstream is
	// unreachable or refuses the CONNECT, a proper 5xx goes back over the
	// H3 stream and the client's Dial sees the real status — instead of
	// an already-upgraded session closing immediately. DialError so the
	// outer proxy loop can fail over to another upstream, same as any
	// other dial failure.
	//
	// WebTransport over HTTP/3 always uses https; RequestURI preserves
	// the request's encoded path and query.
	upstreamURL := "https://" + di.Address + req.URL.RequestURI()
	upstreamResp, upstreamSess, err := dialUpstreamWebTransport(req.Context(), tlsCfg, upstreamURL, req.Header)
	if err != nil {
		return DialError{fmt.Errorf("webtransport upstream dial: %w", err)}
	}
	defer upstreamResp.Body.Close()

	// Response-header ops (gated by Require, if configured) apply to the
	// 200 OK the client will see. webtransport.Server.Upgrade flushes
	// w.Header() along with the status, so setting these before Upgrade
	// is sufficient. Matching against the upstream response mirrors the
	// normal proxy path where upstream response == client response.
	if h.Headers != nil && h.Headers.Response != nil {
		if h.Headers.Response.Require == nil ||
			h.Headers.Response.Require.Match(upstreamResp.StatusCode, upstreamResp.Header) {
			h.Headers.Response.ApplyTo(rw.Header(), repl)
		}
	}

	clientSess, err := wtServer.Upgrade(naked, req)
	if err != nil {
		_ = upstreamSess.CloseWithError(0, "client upgrade failed")
		return terminalError{caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("webtransport upgrade: %w", err))}
	}

	runWebTransportPump(clientSess, upstreamSess, h.logger)
	return nil
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
