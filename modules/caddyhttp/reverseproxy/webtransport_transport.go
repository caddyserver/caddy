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
	"net/url"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Go canonical MIME keys (http.CanonicalHeaderKey). Spec names are
// WT-Available-Protocols / WT-Protocol; HTTP/3 on the wire is lowercase.
const (
	wtAvailableProtocolsHeader = "Wt-Available-Protocols"
	wtProtocolHeader           = "Wt-Protocol"
)

// webtransportProtocol values are the :protocol pseudo-header tokens sent
// by a client that wants to establish a WebTransport session over an HTTP/3
// Extended CONNECT. draft-15 (webtransport-go v0.11.0+) uses "webtransport-h3";
// older draft clients use the legacy "webtransport" token, which the
// webtransport-go server still accepts. Detect both.
const (
	webtransportProtocol        = "webtransport"
	webtransportProtocolDraft15 = "webtransport-h3"
)

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
	return r.ProtoMajor == 3 && r.Method == http.MethodConnect &&
		(r.Proto == webtransportProtocol || r.Proto == webtransportProtocolDraft15)
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
// callers should gate with isWebTransportExtendedConnect. origReq is the
// downstream request (Upgrade / CheckOrigin); req is the upstream-directed
// clone (URL, header_up, SNI expansion).
func (h *Handler) webTransportHijack(rw http.ResponseWriter, req *http.Request, origReq *http.Request, repl *caddy.Replacer, di DialInfo, server *caddyhttp.Server) error {
	wtServer, ok := server.WebTransportServer().(*webtransport.Server)
	if !ok || wtServer == nil {
		return terminalError{caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: server has webtransport disabled or HTTP/3 is not enabled"))}
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
	// webtransport enabled. The upstream dial still needs the HTTP/3
	// transport's TLS config (versions must include "3").
	ht, ok := h.Transport.(*HTTPTransport)
	if !ok || ht.h3Transport == nil {
		return terminalError{caddyhttp.Error(http.StatusBadGateway,
			errors.New("webtransport: requires the http transport with versions [\"3\"]"))}
	}
	tlsCfg := ht.h3Transport.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = new(tls.Config)
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
	//
	// Application protocol negotiation (draft-ietf-webtrans-http3 §3.3)
	// is relayed, not chosen here: parse the offer from the prepared
	// request (so transport and header_up ops apply), put it on the
	// upstream Dialer, and copy the upstream's WT-Protocol onto the
	// client 200. Strip the offer from the forwarded headers so the
	// Dialer remashals a spec-correct list. The shared
	// webtransport.Server keeps ApplicationProtocols empty so Caddy does
	// not independently select a protocol.
	offered := parseWTAvailableProtocols(req.Header)
	req.Header.Del(wtAvailableProtocolsHeader)
	upstreamURL := "https://" + di.Address + req.URL.RequestURI()
	dialStart := time.Now()
	upstreamResp, upstreamSess, err := dialUpstreamWebTransport(req.Context(), tlsCfg, upstreamURL, req.Header, offered, req.Host)
	if err != nil {
		return DialError{fmt.Errorf("webtransport upstream dial: %w", err)}
	}
	defer upstreamResp.Body.Close()
	latency := time.Since(dialStart)

	// Copy filtered upstream headers, then apply header_down. Upgrade
	// flushes rw.Header() with the 200, so this must happen first.
	applyWebTransportResponseHeaders(rw, upstreamResp, h, repl)

	clientSess, err := wtServer.Upgrade(naked, origReq)
	if err != nil {
		_ = upstreamSess.CloseWithError(0, "client upgrade failed")
		return terminalError{caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("webtransport upgrade: %w", err))}
	}
	caddyhttp.RecordHijackedStatus(rw, http.StatusOK)

	runWebTransportPump(clientSess, upstreamSess, h.logger)
	h.recordUpstreamRoundTrip(di, repl, upstreamResp.StatusCode, latency)
	repl.Set("http.reverse_proxy.upstream.duration", time.Since(dialStart))
	repl.Set("http.reverse_proxy.upstream.duration_ms", time.Since(dialStart).Seconds()*1e3)
	return nil
}

// dialUpstreamWebTransport opens a WebTransport session to the upstream at
// urlStr (an https URL), forwarding reqHdr as headers on the Extended
// CONNECT request. The returned session is owned by the caller and must be
// closed when no longer in use. Return-value order matches
// webtransport.Dialer.Dial: (response, session, error).
// applicationProtocols is the client's WT-Available-Protocols offer,
// forwarded so the Dialer will accept the upstream's WT-Protocol choice.
// host, if non-empty, is the prepared Host / :authority for the CONNECT
// (header_up Host); the QUIC dial still uses the URL host.
//
// EXPERIMENTAL: this helper is an internal building block for the upcoming
// WebTransport reverse-proxy transport. Shape and behavior may change.
func dialUpstreamWebTransport(ctx context.Context, tlsCfg *tls.Config, urlStr string, reqHdr http.Header, applicationProtocols []string, host string) (*http.Response, *webtransport.Session, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, err
	}
	dialAddr := u.Host
	if host != "" {
		// Dialer.Dial always sets req.Host from the URL host, so put the
		// prepared Host there. DialAddr keeps the QUIC dial on the real
		// upstream address.
		u.Host = host
		urlStr = u.String()
	}
	d := &webtransport.Dialer{
		TLSClientConfig:      tlsCfg,
		ApplicationProtocols: applicationProtocols,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
		DialAddr: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, dialAddr, tlsCfg, cfg)
		},
	}
	return d.Dial(ctx, urlStr, reqHdr)
}

// applyWebTransportResponseHeaders copies non-hop upstream response headers
// onto the client writer and then applies configured header_down ops, matching
// finalizeResponse for regular proxy responses.
func applyWebTransportResponseHeaders(rw http.ResponseWriter, upstream *http.Response, h *Handler, repl *caddy.Replacer) {
	hdr := upstream.Header.Clone()
	if hdr == nil {
		hdr = make(http.Header)
	}
	removeConnectionHeaders(hdr)
	for _, hop := range hopHeaders {
		hdr.Del(hop)
	}
	if h.Headers != nil && h.Headers.Response != nil {
		if h.Headers.Response.Require == nil ||
			h.Headers.Response.Require.Match(upstream.StatusCode, hdr) {
			h.Headers.Response.ApplyTo(hdr, repl)
		}
	}
	copyHeader(rw.Header(), hdr)
}

// parseWTAvailableProtocols extracts application-protocol tokens from a
// WT-Available-Protocols structured-field list. Missing or malformed
// values are ignored, matching draft-ietf-webtrans-http3 (treat the
// field as absent).
func parseWTAvailableProtocols(h http.Header) []string {
	vals := h.Values(wtAvailableProtocolsHeader)
	if len(vals) == 0 {
		return nil
	}
	list, err := httpsfv.UnmarshalList(vals)
	if err != nil {
		return nil
	}
	var out []string
	for _, item := range list {
		i, ok := item.(httpsfv.Item)
		if !ok {
			return nil
		}
		p, ok := i.Value.(string)
		if !ok {
			return nil
		}
		out = append(out, p)
	}
	return out
}
