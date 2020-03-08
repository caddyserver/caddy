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
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(NTLMTransport{})
}

// NTLMTransport proxies HTTP with NTLM authentication.
// It basically wraps HTTPTransport so that it is compatible with
// NTLM's HTTP-hostile requirements. Specifically, it will use
// HTTPTransport's single, default *http.Transport for all requests
// (unless the client's connection is already mapped to a different
// transport) until a request comes in with an Authorization header
// that has "NTLM" or "Negotiate"; when that happens, NTLMTransport
// maps the client's connection (by its address, req.RemoteAddr)
// to a new transport that is used only by that downstream conn.
// When the upstream connection is closed, the mapping is deleted.
// This preserves NTLM authentication contexts by ensuring that
// client connections use the same upstream connection. It does
// hurt performance a bit, but that's NTLM for you.
//
// This transport also forces HTTP/1.1 and Keep-Alives in order
// for NTLM to succeed.
//
// It is basically the same thing as
// [nginx's paid ntlm directive](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#ntlm)
// (but is free in Caddy!).
type NTLMTransport struct {
	*HTTPTransport

	transports   map[string]*http.Transport
	transportsMu *sync.RWMutex
}

// CaddyModule returns the Caddy module information.
func (NTLMTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.reverse_proxy.transport.http_ntlm",
		New: func() caddy.Module {
			m := new(NTLMTransport)
			m.HTTPTransport = new(HTTPTransport)
			return m
		},
	}
}

// Provision sets up the transport module.
func (n *NTLMTransport) Provision(ctx caddy.Context) error {
	n.transports = make(map[string]*http.Transport)
	n.transportsMu = new(sync.RWMutex)

	if n.HTTPTransport == nil {
		n.HTTPTransport = new(HTTPTransport)
	}

	// NTLM requires HTTP/1.1
	n.HTTPTransport.Versions = []string{"1.1"}

	// NLTM requires keep-alive
	if n.HTTPTransport.KeepAlive != nil {
		enabled := true
		n.HTTPTransport.KeepAlive.Enabled = &enabled
	}

	// set up the underlying transport, since we
	// rely on it for the heavy lifting
	err := n.HTTPTransport.Provision(ctx)
	if err != nil {
		return err
	}

	return nil
}

// RoundTrip implements http.RoundTripper. It basically wraps
// the underlying HTTPTransport.Transport in a way that preserves
// NTLM context by mapping transports/connections. Note that this
// method does not call n.HTTPTransport.RoundTrip (our own method),
// but the underlying n.HTTPTransport.Transport.RoundTrip (standard
// library's method).
func (n *NTLMTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	n.HTTPTransport.setScheme(req)

	// when the upstream connection is closed, make sure
	// we close the downstream connection with the client
	// when this request is done; we only do this if
	// using a bound transport
	closeDownstreamIfClosedUpstream := func() {
		n.transportsMu.Lock()
		if _, ok := n.transports[req.RemoteAddr]; !ok {
			req.Close = true
		}
		n.transportsMu.Unlock()
	}

	// first, see if this downstream connection is
	// already bound to a particular transport
	// (transports are abstractions over connections
	// to our upstream, and NTLM auth requires
	// preserving authentication state for separate
	// connections over multiple roundtrips, sigh)
	n.transportsMu.Lock()
	transport, ok := n.transports[req.RemoteAddr]
	if ok {
		n.transportsMu.Unlock()
		defer closeDownstreamIfClosedUpstream()
		return transport.RoundTrip(req)
	}

	// otherwise, start by assuming we will use
	// the default transport that carries all
	// normal/non-NTLM-authenticated requests
	transport = n.HTTPTransport.Transport

	// but if this request begins the NTLM authentication
	// process, we need to pin it to a specific transport
	if requestHasAuth(req) {
		var err error
		transport, err = n.newTransport()
		if err != nil {
			return nil, fmt.Errorf("making new transport for %s: %v", req.RemoteAddr, err)
		}
		n.transports[req.RemoteAddr] = transport
		defer closeDownstreamIfClosedUpstream()
	}
	n.transportsMu.Unlock()

	// finally, do the roundtrip with the transport we selected
	return transport.RoundTrip(req)
}

// newTransport makes an NTLM-compatible transport.
func (n *NTLMTransport) newTransport() (*http.Transport, error) {
	// start with a regular HTTP transport
	transport, err := n.HTTPTransport.newTransport()
	if err != nil {
		return nil, err
	}

	// we need to wrap upstream connections so we can
	// clean up in two ways when that connection is
	// closed: 1) destroy the transport that housed
	// this connection, and 2) use that as a signal
	// to close the connection to the downstream.
	wrappedDialContext := transport.DialContext

	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn2, err := wrappedDialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		req := ctx.Value(caddyhttp.OriginalRequestCtxKey).(http.Request)
		conn := &unbinderConn{Conn: conn2, ntlm: n, clientAddr: req.RemoteAddr}
		return conn, nil
	}

	return transport, nil
}

// Cleanup implements caddy.CleanerUpper and closes any idle connections.
func (n *NTLMTransport) Cleanup() error {
	if err := n.HTTPTransport.Cleanup(); err != nil {
		return err
	}

	n.transportsMu.Lock()
	for _, t := range n.transports {
		t.CloseIdleConnections()
	}
	n.transports = make(map[string]*http.Transport)
	n.transportsMu.Unlock()

	return nil
}

// deleteTransportsForClient deletes (unmaps) transports that are
// associated with clientAddr (a req.RemoteAddr value).
func (n *NTLMTransport) deleteTransportsForClient(clientAddr string) {
	n.transportsMu.Lock()
	for key := range n.transports {
		if key == clientAddr {
			delete(n.transports, key)
		}
	}
	n.transportsMu.Unlock()
}

// requestHasAuth returns true if req has an Authorization
// header with values "NTLM" or "Negotiate".
func requestHasAuth(req *http.Request) bool {
	for _, val := range req.Header["Authorization"] {
		if strings.HasPrefix(val, "NTLM") ||
			strings.HasPrefix(val, "Negotiate") {
			return true
		}
	}
	return false
}

// unbinderConn is used to wrap upstream connections
// so that we know when they are closed and can clean
// up after that.
type unbinderConn struct {
	net.Conn
	clientAddr string
	ntlm       *NTLMTransport
}

func (uc *unbinderConn) Close() error {
	uc.ntlm.deleteTransportsForClient(uc.clientAddr)
	return uc.Conn.Close()
}

// Interface guards
var (
	_ caddy.Provisioner  = (*NTLMTransport)(nil)
	_ http.RoundTripper  = (*NTLMTransport)(nil)
	_ caddy.CleanerUpper = (*NTLMTransport)(nil)
)
