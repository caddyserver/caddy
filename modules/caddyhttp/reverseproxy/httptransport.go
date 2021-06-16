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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	weakrand "math/rand"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"golang.org/x/net/http2"
)

func init() {
	caddy.RegisterModule(HTTPTransport{})
}

// HTTPTransport is essentially a configuration wrapper for http.Transport.
// It defines a JSON structure useful when configuring the HTTP transport
// for Caddy's reverse proxy. It builds its http.Transport at Provision.
type HTTPTransport struct {
	// TODO: It's possible that other transports (like fastcgi) might be
	// able to borrow/use at least some of these config fields; if so,
	// maybe move them into a type called CommonTransport and embed it?

	// Configures the DNS resolver used to resolve the IP address of upstream hostnames.
	Resolver *UpstreamResolver `json:"resolver,omitempty"`

	// Configures TLS to the upstream. Setting this to an empty struct
	// is sufficient to enable TLS with reasonable defaults.
	TLS *TLSConfig `json:"tls,omitempty"`

	// Configures HTTP Keep-Alive (enabled by default). Should only be
	// necessary if rigorous testing has shown that tuning this helps
	// improve performance.
	KeepAlive *KeepAlive `json:"keep_alive,omitempty"`

	// Whether to enable compression to upstream. Default: true
	Compression *bool `json:"compression,omitempty"`

	// Maximum number of connections per host. Default: 0 (no limit)
	MaxConnsPerHost int `json:"max_conns_per_host,omitempty"`

	// How long to wait before timing out trying to connect to
	// an upstream.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// How long to wait before spawning an RFC 6555 Fast Fallback
	// connection. A negative value disables this.
	FallbackDelay caddy.Duration `json:"dial_fallback_delay,omitempty"`

	// How long to wait for reading response headers from server.
	ResponseHeaderTimeout caddy.Duration `json:"response_header_timeout,omitempty"`

	// The length of time to wait for a server's first response
	// headers after fully writing the request headers if the
	// request has a header "Expect: 100-continue".
	ExpectContinueTimeout caddy.Duration `json:"expect_continue_timeout,omitempty"`

	// The maximum bytes to read from response headers.
	MaxResponseHeaderSize int64 `json:"max_response_header_size,omitempty"`

	// The size of the write buffer in bytes.
	WriteBufferSize int `json:"write_buffer_size,omitempty"`

	// The size of the read buffer in bytes.
	ReadBufferSize int `json:"read_buffer_size,omitempty"`

	// The versions of HTTP to support. As a special case, "h2c"
	// can be specified to use H2C (HTTP/2 over Cleartext) to the
	// upstream (this feature is experimental and subject to
	// change or removal). Default: ["1.1", "2"]
	Versions []string `json:"versions,omitempty"`

	// The pre-configured underlying HTTP transport.
	Transport *http.Transport `json:"-"`

	h2cTransport *http2.Transport
}

// CaddyModule returns the Caddy module information.
func (HTTPTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.http",
		New: func() caddy.Module { return new(HTTPTransport) },
	}
}

// Provision sets up h.Transport with a *http.Transport
// that is ready to use.
func (h *HTTPTransport) Provision(ctx caddy.Context) error {
	if len(h.Versions) == 0 {
		h.Versions = []string{"1.1", "2"}
	}

	rt, err := h.NewTransport(ctx)
	if err != nil {
		return err
	}
	h.Transport = rt

	// if h2c is enabled, configure its transport (std lib http.Transport
	// does not "HTTP/2 over cleartext TCP")
	if sliceContains(h.Versions, "h2c") {
		// crafting our own http2.Transport doesn't allow us to utilize
		// most of the customizations/preferences on the http.Transport,
		// because, for some reason, only http2.ConfigureTransport()
		// is allowed to set the unexported field that refers to a base
		// http.Transport config; oh well
		h2t := &http2.Transport{
			// kind of a hack, but for plaintext/H2C requests, pretend to dial TLS
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				// TODO: no context, thus potentially wrong dial info
				return net.Dial(network, addr)
			},
			AllowHTTP: true,
		}
		if h.Compression != nil {
			h2t.DisableCompression = !*h.Compression
		}
		h.h2cTransport = h2t
	}

	return nil
}

// NewTransport builds a standard-lib-compatible http.Transport value from h.
func (h *HTTPTransport) NewTransport(ctx caddy.Context) (*http.Transport, error) {
	dialer := &net.Dialer{
		Timeout:       time.Duration(h.DialTimeout),
		FallbackDelay: time.Duration(h.FallbackDelay),
	}

	if h.Resolver != nil {
		for _, v := range h.Resolver.Addresses {
			addr, err := caddy.ParseNetworkAddress(v)
			if err != nil {
				return nil, err
			}
			if addr.PortRangeSize() != 1 {
				return nil, fmt.Errorf("resolver address must have exactly one address; cannot call %v", addr)
			}
			h.Resolver.netAddrs = append(h.Resolver.netAddrs, addr)
		}
		d := &net.Dialer{
			Timeout:       time.Duration(h.DialTimeout),
			FallbackDelay: time.Duration(h.FallbackDelay),
		}
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				//nolint:gosec
				addr := h.Resolver.netAddrs[weakrand.Intn(len(h.Resolver.netAddrs))]
				return d.DialContext(ctx, addr.Network, addr.JoinHostPort(0))
			},
		}
	}

	rt := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// the proper dialing information should be embedded into the request's context
			if dialInfo, ok := GetDialInfo(ctx); ok {
				network = dialInfo.Network
				address = dialInfo.Address
			}
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				// identify this error as one that occurred during
				// dialing, which can be important when trying to
				// decide whether to retry a request
				return nil, DialError{err}
			}
			return conn, nil
		},
		MaxConnsPerHost:        h.MaxConnsPerHost,
		ResponseHeaderTimeout:  time.Duration(h.ResponseHeaderTimeout),
		ExpectContinueTimeout:  time.Duration(h.ExpectContinueTimeout),
		MaxResponseHeaderBytes: h.MaxResponseHeaderSize,
		WriteBufferSize:        h.WriteBufferSize,
		ReadBufferSize:         h.ReadBufferSize,
	}

	if h.TLS != nil {
		rt.TLSHandshakeTimeout = time.Duration(h.TLS.HandshakeTimeout)
		var err error
		rt.TLSClientConfig, err = h.TLS.MakeTLSClientConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("making TLS client config: %v", err)
		}
	}

	if h.KeepAlive != nil {
		dialer.KeepAlive = time.Duration(h.KeepAlive.ProbeInterval)
		if h.KeepAlive.Enabled != nil {
			rt.DisableKeepAlives = !*h.KeepAlive.Enabled
		}
		rt.MaxIdleConns = h.KeepAlive.MaxIdleConns
		rt.MaxIdleConnsPerHost = h.KeepAlive.MaxIdleConnsPerHost
		rt.IdleConnTimeout = time.Duration(h.KeepAlive.IdleConnTimeout)
	}

	if h.Compression != nil {
		rt.DisableCompression = !*h.Compression
	}

	if sliceContains(h.Versions, "2") {
		if err := http2.ConfigureTransport(rt); err != nil {
			return nil, err
		}
	}

	return rt, nil
}

// RoundTrip implements http.RoundTripper.
func (h *HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h.SetScheme(req)

	// if H2C ("HTTP/2 over cleartext") is enabled and the upstream request is
	// HTTP/2 without TLS, use the alternate H2C-capable transport instead
	if req.ProtoMajor == 2 && req.URL.Scheme == "http" && h.h2cTransport != nil {
		return h.h2cTransport.RoundTrip(req)
	}

	return h.Transport.RoundTrip(req)
}

// SetScheme ensures that the outbound request req
// has the scheme set in its URL; the underlying
// http.Transport requires a scheme to be set.
func (h *HTTPTransport) SetScheme(req *http.Request) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
		if h.TLS != nil {
			req.URL.Scheme = "https"
		}
	}
}

// TLSEnabled returns true if TLS is enabled.
func (h HTTPTransport) TLSEnabled() bool {
	return h.TLS != nil
}

// EnableTLS enables TLS on the transport.
func (h *HTTPTransport) EnableTLS(base *TLSConfig) error {
	h.TLS = base
	return nil
}

// Cleanup implements caddy.CleanerUpper and closes any idle connections.
func (h HTTPTransport) Cleanup() error {
	if h.Transport == nil {
		return nil
	}
	h.Transport.CloseIdleConnections()
	return nil
}

// TLSConfig holds configuration related to the TLS configuration for the
// transport/client.
type TLSConfig struct {
	// Optional list of base64-encoded DER-encoded CA certificates to trust.
	RootCAPool []string `json:"root_ca_pool,omitempty"`

	// List of PEM-encoded CA certificate files to add to the same trust
	// store as RootCAPool (or root_ca_pool in the JSON).
	RootCAPEMFiles []string `json:"root_ca_pem_files,omitempty"`

	// PEM-encoded client certificate filename to present to servers.
	ClientCertificateFile string `json:"client_certificate_file,omitempty"`

	// PEM-encoded key to use with the client certificate.
	ClientCertificateKeyFile string `json:"client_certificate_key_file,omitempty"`

	// If specified, Caddy will use and automate a client certificate
	// with this subject name.
	ClientCertificateAutomate string `json:"client_certificate_automate,omitempty"`

	// If true, TLS verification of server certificates will be disabled.
	// This is insecure and may be removed in the future. Do not use this
	// option except in testing or local development environments.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// The duration to allow a TLS handshake to a server.
	HandshakeTimeout caddy.Duration `json:"handshake_timeout,omitempty"`

	// The server name (SNI) to use in TLS handshakes.
	ServerName string `json:"server_name,omitempty"`
}

// MakeTLSClientConfig returns a tls.Config usable by a client to a backend.
// If there is no custom TLS configuration, a nil config may be returned.
func (t TLSConfig) MakeTLSClientConfig(ctx caddy.Context) (*tls.Config, error) {
	cfg := new(tls.Config)

	// client auth
	if t.ClientCertificateFile != "" && t.ClientCertificateKeyFile == "" {
		return nil, fmt.Errorf("client_certificate_file specified without client_certificate_key_file")
	}
	if t.ClientCertificateFile == "" && t.ClientCertificateKeyFile != "" {
		return nil, fmt.Errorf("client_certificate_key_file specified without client_certificate_file")
	}
	if t.ClientCertificateFile != "" && t.ClientCertificateKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.ClientCertificateFile, t.ClientCertificateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate key pair: %v", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if t.ClientCertificateAutomate != "" {
		// TODO: use or enable ctx.IdentityCredentials() ...
		tlsAppIface, err := ctx.App("tls")
		if err != nil {
			return nil, fmt.Errorf("getting tls app: %v", err)
		}
		tlsApp := tlsAppIface.(*caddytls.TLS)
		err = tlsApp.Manage([]string{t.ClientCertificateAutomate})
		if err != nil {
			return nil, fmt.Errorf("managing client certificate: %v", err)
		}
		cfg.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			certs := tlsApp.AllMatchingCertificates(t.ClientCertificateAutomate)
			var err error
			for _, cert := range certs {
				err = cri.SupportsCertificate(&cert.Certificate)
				if err == nil {
					return &cert.Certificate, nil
				}
			}
			return nil, err
		}
	}

	// trusted root CAs
	if len(t.RootCAPool) > 0 || len(t.RootCAPEMFiles) > 0 {
		rootPool := x509.NewCertPool()
		for _, encodedCACert := range t.RootCAPool {
			caCert, err := decodeBase64DERCert(encodedCACert)
			if err != nil {
				return nil, fmt.Errorf("parsing CA certificate: %v", err)
			}
			rootPool.AddCert(caCert)
		}
		for _, pemFile := range t.RootCAPEMFiles {
			pemData, err := ioutil.ReadFile(pemFile)
			if err != nil {
				return nil, fmt.Errorf("failed reading ca cert: %v", err)
			}
			rootPool.AppendCertsFromPEM(pemData)

		}
		cfg.RootCAs = rootPool
	}

	// custom SNI
	cfg.ServerName = t.ServerName

	// throw all security out the window
	cfg.InsecureSkipVerify = t.InsecureSkipVerify

	// only return a config if it's not empty
	if reflect.DeepEqual(cfg, new(tls.Config)) {
		return nil, nil
	}

	return cfg, nil
}

// UpstreamResolver holds the set of addresses of DNS resolvers of
// upstream addresses
type UpstreamResolver struct {
	// The addresses of DNS resolvers to use when looking up the addresses of proxy upstreams.
	// It accepts [network addresses](/docs/conventions#network-addresses)
	// with port range of only 1. If the host is an IP address, it will be dialed directly to resolve the upstream server.
	// If the host is not an IP address, the addresses are resolved using the [name resolution convention](https://golang.org/pkg/net/#hdr-Name_Resolution) of the Go standard library.
	// If the array contains more than 1 resolver address, one is chosen at random.
	Addresses []string `json:"addresses,omitempty"`
	netAddrs  []caddy.NetworkAddress
}

// KeepAlive holds configuration pertaining to HTTP Keep-Alive.
type KeepAlive struct {
	// Whether HTTP Keep-Alive is enabled. Default: true
	Enabled *bool `json:"enabled,omitempty"`

	// How often to probe for liveness.
	ProbeInterval caddy.Duration `json:"probe_interval,omitempty"`

	// Maximum number of idle connections. Default: 0, which means no limit.
	MaxIdleConns int `json:"max_idle_conns,omitempty"`

	// Maximum number of idle connections per host. Default: 32.
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`

	// How long connections should be kept alive when idle. Default: 0, which means no timeout.
	IdleConnTimeout caddy.Duration `json:"idle_timeout,omitempty"`
}

// decodeBase64DERCert base64-decodes, then DER-decodes, certStr.
func decodeBase64DERCert(certStr string) (*x509.Certificate, error) {
	// decode base64
	derBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, err
	}

	// parse the DER-encoded certificate
	return x509.ParseCertificate(derBytes)
}

// sliceContains returns true if needle is in haystack.
func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// Interface guards
var (
	_ caddy.Provisioner  = (*HTTPTransport)(nil)
	_ http.RoundTripper  = (*HTTPTransport)(nil)
	_ caddy.CleanerUpper = (*HTTPTransport)(nil)
	_ TLSTransport       = (*HTTPTransport)(nil)
)
