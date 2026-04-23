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
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
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
// upstream, dials the upstream-side session, upgrades the client-side
// session, and runs the session pump until both sides close.
//
// The upstream is dialed *before* the client is upgraded so that a refused
// or unreachable upstream surfaces as a real 5xx on the client's Dial —
// not as a bare post-upgrade session close. There are no retries: WT
// sessions are long-lived and not idempotent.
//
// The outgoing CONNECT is prepared with the same Rewrite, hop-by-hop
// stripping, X-Forwarded-*/Via, transport- and user-configured header ops
// as the normal proxy path. Response-header ops (gated by `Require`, if
// configured) apply to the headers the client sees on the 200 OK.
// Requests that reach this function are already known to be WebTransport;
// callers should gate with isWebTransportExtendedConnect.
func (h *Handler) serveWebTransport(w http.ResponseWriter, r *http.Request) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	start := time.Now()
	defer func() {
		d := time.Since(start)
		repl.Set("http.reverse_proxy.duration", d)
		repl.Set("http.reverse_proxy.duration_ms", d.Seconds()*1e3)
	}()

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

	if h.LoadBalancing == nil || h.LoadBalancing.SelectionPolicy == nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: load balancer is not configured"))
	}

	// Resolve the candidate upstream set (static or dynamic) and select
	// one. WT sessions are long-lived and not idempotent, so there are no
	// retries; picking once matches how operators expect WT to behave.
	upstreams := h.Upstreams
	if h.DynamicUpstreams != nil {
		dynUpstreams, err := h.DynamicUpstreams.GetUpstreams(r)
		if err != nil {
			if c := h.logger.Check(zapcore.WarnLevel, "webtransport: dynamic upstreams failed; falling back to static"); c != nil {
				c.Write(zap.Error(err))
			}
		} else {
			upstreams = dynUpstreams
			for _, dUp := range dynUpstreams {
				h.provisionUpstream(dUp, true)
			}
		}
	}
	upstream := h.LoadBalancing.SelectionPolicy.Select(upstreams, r, w)
	if upstream == nil {
		return caddyhttp.Error(http.StatusBadGateway, errNoUpstream)
	}

	// Resolve per-upstream placeholders (addresses may include them) and
	// publish the {http.reverse_proxy.upstream.*} replacer values before
	// we commit to upgrading — so any client-side failure logs downstream
	// see the selected upstream too.
	dialInfo, err := upstream.fillDialInfo(repl)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("webtransport: making dial info: %w", err))
	}
	repl.Set("http.reverse_proxy.upstream.address", dialInfo.String())
	repl.Set("http.reverse_proxy.upstream.hostport", dialInfo.Address)
	repl.Set("http.reverse_proxy.upstream.host", dialInfo.Host)
	repl.Set("http.reverse_proxy.upstream.port", dialInfo.Port)
	repl.Set("http.reverse_proxy.upstream.requests", upstream.Host.NumRequests())
	repl.Set("http.reverse_proxy.upstream.max_requests", upstream.MaxRequests)
	repl.Set("http.reverse_proxy.upstream.fails", upstream.Host.Fails())

	// Prepare the outgoing request the same way normal proxying does —
	// Rewrite, hop-by-hop stripping, X-Forwarded-*, Via, etc. — then apply
	// transport and user header ops. prepareRequest's body-buffering and
	// Early-Data paths are no-ops for a CONNECT request (empty body).
	clonedReq, err := h.prepareRequest(r, repl)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("webtransport: preparing request: %w", err))
	}
	if h.transportHeaderOps != nil {
		h.transportHeaderOps.ApplyToRequest(clonedReq)
	}
	if h.Headers != nil && h.Headers.Request != nil {
		h.Headers.Request.ApplyToRequest(clonedReq)
	}

	// Reach the naked http3 response writer so Upgrade's type assertions
	// succeed through Caddy's wrapper chain. Done before dialing so we
	// fail fast if the writer stack is unexpectedly incompatible.
	naked, ok := caddyhttp.UnwrapResponseWriterAs[caddywt.Writer](w)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("webtransport: response writer does not support WebTransport upgrade"))
	}

	// Dial the upstream BEFORE upgrading the client. If the upstream is
	// unreachable or refuses the CONNECT, a proper 5xx goes back over the
	// H3 stream and the client's Dial sees the real status — instead of
	// an already-upgraded session closing immediately.
	ht := h.Transport.(*HTTPTransport)
	upstreamURL := buildWebTransportUpstreamURL(dialInfo.Address, clonedReq)
	upstreamResp, upstreamSess, err := dialUpstreamWebTransport(r.Context(), ht.h3Transport.TLSClientConfig, upstreamURL, clonedReq.Header)
	if err != nil {
		h.countFailure(upstream)
		if c := h.logger.Check(zapcore.ErrorLevel, "webtransport upstream dial failed"); c != nil {
			c.Write(
				zap.String("upstream", upstreamURL),
				zap.Error(err),
			)
		}
		return caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("webtransport upstream dial: %w", err))
	}
	defer upstreamResp.Body.Close()

	// Response-header ops (gated by Require, if configured) are applied to
	// the 200 OK the client will see. webtransport.Server.Upgrade flushes
	// w.Header() along with the status, so setting these before Upgrade is
	// sufficient. Matching against the upstream response mirrors the normal
	// proxy path where upstream response == client response.
	if h.Headers != nil && h.Headers.Response != nil {
		if h.Headers.Response.Require == nil ||
			h.Headers.Response.Require.Match(upstreamResp.StatusCode, upstreamResp.Header) {
			h.Headers.Response.ApplyTo(w.Header(), repl)
		}
	}

	clientSess, err := wtServer.Upgrade(naked, r)
	if err != nil {
		_ = upstreamSess.CloseWithError(0, "client upgrade failed")
		if c := h.logger.Check(zapcore.DebugLevel, "webtransport client upgrade failed"); c != nil {
			c.Write(zap.Error(err))
		}
		return caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("webtransport upgrade: %w", err))
	}

	// Track the session in the same upstream counters the normal proxy
	// path maintains: Host.NumRequests drives MaxRequests gating and
	// least-connections selection; the per-address in-flight counter
	// feeds the admin API's upstream stats.
	_ = dialInfo.Upstream.Host.countRequest(1)
	incInFlightRequest(dialInfo.Address)
	defer func() {
		_ = dialInfo.Upstream.Host.countRequest(-1)
		decInFlightRequest(dialInfo.Address)
	}()

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
