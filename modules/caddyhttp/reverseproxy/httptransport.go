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
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(HTTPTransport{})
}

// TODO: This is the default transport, basically just http.Transport, but we define JSON struct tags...
type HTTPTransport struct {
	// TODO: Actually this is where the TLS config should go, technically...
	// as well as keepalives and dial timeouts...
	// TODO: It's possible that other transports (like fastcgi) might be
	// able to borrow/use at least some of these config fields; if so,
	// move them into a type called CommonTransport and embed it

	TLS                   *TLSConfig     `json:"tls,omitempty"`
	KeepAlive             *KeepAlive     `json:"keep_alive,omitempty"`
	Compression           *bool          `json:"compression,omitempty"`
	MaxConnsPerHost       int            `json:"max_conns_per_host,omitempty"` // TODO: NOTE: we use our health check stuff to enforce max REQUESTS per host, but this is connections
	DialTimeout           caddy.Duration `json:"dial_timeout,omitempty"`
	FallbackDelay         caddy.Duration `json:"dial_fallback_delay,omitempty"`
	ResponseHeaderTimeout caddy.Duration `json:"response_header_timeout,omitempty"`
	ExpectContinueTimeout caddy.Duration `json:"expect_continue_timeout,omitempty"`
	MaxResponseHeaderSize int64          `json:"max_response_header_size,omitempty"`
	WriteBufferSize       int            `json:"write_buffer_size,omitempty"`
	ReadBufferSize        int            `json:"read_buffer_size,omitempty"`
	// TODO: ProxyConnectHeader?

	RoundTripper http.RoundTripper `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (HTTPTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.reverse_proxy.transport.http",
		New:  func() caddy.Module { return new(HTTPTransport) },
	}
}

func (h *HTTPTransport) Provision(ctx caddy.Context) error {
	dialer := &net.Dialer{
		Timeout:       time.Duration(h.DialTimeout),
		FallbackDelay: time.Duration(h.FallbackDelay),
		// TODO: Resolver
	}
	rt := &http.Transport{
		DialContext:            dialer.DialContext,
		MaxConnsPerHost:        h.MaxConnsPerHost,
		ResponseHeaderTimeout:  time.Duration(h.ResponseHeaderTimeout),
		ExpectContinueTimeout:  time.Duration(h.ExpectContinueTimeout),
		MaxResponseHeaderBytes: h.MaxResponseHeaderSize,
		WriteBufferSize:        h.WriteBufferSize,
		ReadBufferSize:         h.ReadBufferSize,
	}

	if h.TLS != nil {
		rt.TLSHandshakeTimeout = time.Duration(h.TLS.HandshakeTimeout)
		// TODO: rest of TLS config
	}

	if h.KeepAlive != nil {
		dialer.KeepAlive = time.Duration(h.KeepAlive.ProbeInterval)

		if enabled := h.KeepAlive.Enabled; enabled != nil {
			rt.DisableKeepAlives = !*enabled
		}
		rt.MaxIdleConns = h.KeepAlive.MaxIdleConns
		rt.MaxIdleConnsPerHost = h.KeepAlive.MaxIdleConnsPerHost
		rt.IdleConnTimeout = time.Duration(h.KeepAlive.IdleConnTimeout)
	}

	if h.Compression != nil {
		rt.DisableCompression = !*h.Compression
	}

	h.RoundTripper = rt

	return nil
}

func (h HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return h.RoundTripper.RoundTrip(req)
}

type TLSConfig struct {
	CAPool             []string       `json:"ca_pool,omitempty"`
	ClientCertificate  string         `json:"client_certificate,omitempty"`
	InsecureSkipVerify bool           `json:"insecure_skip_verify,omitempty"`
	HandshakeTimeout   caddy.Duration `json:"handshake_timeout,omitempty"`
}

type KeepAlive struct {
	Enabled             *bool          `json:"enabled,omitempty"`
	ProbeInterval       caddy.Duration `json:"probe_interval,omitempty"`
	MaxIdleConns        int            `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost int            `json:"max_idle_conns_per_host,omitempty"`
	IdleConnTimeout     caddy.Duration `json:"idle_timeout,omitempty"` // how long should connections be kept alive when idle
}

var (
	defaultDialer = net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// TODO: does this need to be configured to enable HTTP/2?
	defaultTransport = &http.Transport{
		DialContext:         defaultDialer.DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		IdleConnTimeout:     2 * time.Minute,
	}
)
