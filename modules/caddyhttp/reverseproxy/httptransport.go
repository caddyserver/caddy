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
	"encoding/json"
	"fmt"
	weakrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
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

	// If non-empty, which PROXY protocol version to send when
	// connecting to an upstream. Default: off.
	ProxyProtocol string `json:"proxy_protocol,omitempty"`

	// URL to the server that the HTTP transport will use to proxy
	// requests to the upstream. See http.Transport.Proxy for
	// information regarding supported protocols. This value takes
	// precedence over `HTTP_PROXY`, etc.
	//
	// Providing a value to this parameter results in
	// requests flowing through the reverse_proxy in the following
	// way:
	//
	// User Agent ->
	//  reverse_proxy ->
	//  forward_proxy_url -> upstream
	//
	// Default: http.ProxyFromEnvironment
	ForwardProxyURL string `json:"forward_proxy_url,omitempty"`

	// How long to wait before timing out trying to connect to
	// an upstream. Default: `3s`.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// How long to wait before spawning an RFC 6555 Fast Fallback
	// connection. A negative value disables this. Default: `300ms`.
	FallbackDelay caddy.Duration `json:"dial_fallback_delay,omitempty"`

	// How long to wait for reading response headers from server. Default: No timeout.
	ResponseHeaderTimeout caddy.Duration `json:"response_header_timeout,omitempty"`

	// The length of time to wait for a server's first response
	// headers after fully writing the request headers if the
	// request has a header "Expect: 100-continue". Default: No timeout.
	ExpectContinueTimeout caddy.Duration `json:"expect_continue_timeout,omitempty"`

	// The maximum bytes to read from response headers. Default: `10MiB`.
	MaxResponseHeaderSize int64 `json:"max_response_header_size,omitempty"`

	// The size of the write buffer in bytes. Default: `4KiB`.
	WriteBufferSize int `json:"write_buffer_size,omitempty"`

	// The size of the read buffer in bytes. Default: `4KiB`.
	ReadBufferSize int `json:"read_buffer_size,omitempty"`

	// The maximum time to wait for next read from backend. Default: no timeout.
	ReadTimeout caddy.Duration `json:"read_timeout,omitempty"`

	// The maximum time to wait for next write to backend. Default: no timeout.
	WriteTimeout caddy.Duration `json:"write_timeout,omitempty"`

	// The versions of HTTP to support. As a special case, "h2c"
	// can be specified to use H2C (HTTP/2 over Cleartext) to the
	// upstream (this feature is experimental and subject to
	// change or removal). Default: ["1.1", "2"]
	//
	// EXPERIMENTAL: "3" enables HTTP/3, but it must be the only
	// version specified if enabled. Additionally, HTTPS must be
	// enabled to the upstream as HTTP/3 requires TLS. Subject
	// to change or removal while experimental.
	Versions []string `json:"versions,omitempty"`

	// Specify the address to bind to when connecting to an upstream. In other words,
	// it is the address the upstream sees as the remote address.
	LocalAddress string `json:"local_address,omitempty"`

	// The pre-configured underlying HTTP transport.
	Transport *http.Transport `json:"-"`

	h2cTransport *http2.Transport
	h3Transport  *http3.Transport // TODO: EXPERIMENTAL (May 2024)
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

	return nil
}

// NewTransport builds a standard-lib-compatible http.Transport value from h.
func (h *HTTPTransport) NewTransport(caddyCtx caddy.Context) (*http.Transport, error) {
	// Set keep-alive defaults if it wasn't otherwise configured
	if h.KeepAlive == nil {
		h.KeepAlive = &KeepAlive{
			ProbeInterval:       caddy.Duration(30 * time.Second),
			IdleConnTimeout:     caddy.Duration(2 * time.Minute),
			MaxIdleConnsPerHost: 32, // seems about optimal, see #2805
		}
	}

	// Set a relatively short default dial timeout.
	// This is helpful to make load-balancer retries more speedy.
	if h.DialTimeout == 0 {
		h.DialTimeout = caddy.Duration(3 * time.Second)
	}

	dialer := &net.Dialer{
		Timeout:       time.Duration(h.DialTimeout),
		FallbackDelay: time.Duration(h.FallbackDelay),
	}

	if h.LocalAddress != "" {
		netaddr, err := caddy.ParseNetworkAddressWithDefaults(h.LocalAddress, "tcp", 0)
		if err != nil {
			return nil, err
		}
		if netaddr.PortRangeSize() > 1 {
			return nil, fmt.Errorf("local_address must be a single address, not a port range")
		}
		switch netaddr.Network {
		case "tcp", "tcp4", "tcp6":
			dialer.LocalAddr, err = net.ResolveTCPAddr(netaddr.Network, netaddr.JoinHostPort(0))
			if err != nil {
				return nil, err
			}
		case "unix", "unixgram", "unixpacket":
			dialer.LocalAddr, err = net.ResolveUnixAddr(netaddr.Network, netaddr.JoinHostPort(0))
			if err != nil {
				return nil, err
			}
		case "udp", "udp4", "udp6":
			return nil, fmt.Errorf("local_address must be a TCP address, not a UDP address")
		default:
			return nil, fmt.Errorf("unsupported network")
		}
	}
	if h.Resolver != nil {
		err := h.Resolver.ParseAddresses()
		if err != nil {
			return nil, err
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

	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		// For unix socket upstreams, we need to recover the dial info from
		// the request's context, because the Host on the request's URL
		// will have been modified by directing the request, overwriting
		// the unix socket filename.
		// Also, we need to avoid overwriting the address at this point
		// when not necessary, because http.ProxyFromEnvironment may have
		// modified the address according to the user's env proxy config.
		if dialInfo, ok := GetDialInfo(ctx); ok {
			if strings.HasPrefix(dialInfo.Network, "unix") {
				network = dialInfo.Network
				address = dialInfo.Address
			}
		}

		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			// identify this error as one that occurred during
			// dialing, which can be important when trying to
			// decide whether to retry a request
			return nil, DialError{err}
		}

		if h.ProxyProtocol != "" {
			proxyProtocolInfo, ok := caddyhttp.GetVar(ctx, proxyProtocolInfoVarKey).(ProxyProtocolInfo)
			if !ok {
				return nil, fmt.Errorf("failed to get proxy protocol info from context")
			}
			var proxyv byte
			switch h.ProxyProtocol {
			case "v1":
				proxyv = 1
			case "v2":
				proxyv = 2
			default:
				return nil, fmt.Errorf("unexpected proxy protocol version")
			}

			// The src and dst have to be of the same address family. As we don't know the original
			// dst address (it's kind of impossible to know) and this address is generally of very
			// little interest, we just set it to all zeros.
			var destAddr net.Addr
			switch {
			case proxyProtocolInfo.AddrPort.Addr().Is4():
				destAddr = &net.TCPAddr{
					IP: net.IPv4zero,
				}
			case proxyProtocolInfo.AddrPort.Addr().Is6():
				destAddr = &net.TCPAddr{
					IP: net.IPv6zero,
				}
			default:
				return nil, fmt.Errorf("unexpected remote addr type in proxy protocol info")
			}
			sourceAddr := &net.TCPAddr{
				IP:   proxyProtocolInfo.AddrPort.Addr().AsSlice(),
				Port: int(proxyProtocolInfo.AddrPort.Port()),
				Zone: proxyProtocolInfo.AddrPort.Addr().Zone(),
			}
			header := proxyproto.HeaderProxyFromAddrs(proxyv, sourceAddr, destAddr)

			// retain the log message structure
			switch h.ProxyProtocol {
			case "v1":
				caddyCtx.Logger().Debug("sending proxy protocol header v1", zap.Any("header", header))
			case "v2":
				caddyCtx.Logger().Debug("sending proxy protocol header v2", zap.Any("header", header))
			}

			_, err = header.WriteTo(conn)
			if err != nil {
				// identify this error as one that occurred during
				// dialing, which can be important when trying to
				// decide whether to retry a request
				return nil, DialError{err}
			}
		}

		// if read/write timeouts are configured and this is a TCP connection,
		// enforce the timeouts by wrapping the connection with our own type
		if tcpConn, ok := conn.(*net.TCPConn); ok && (h.ReadTimeout > 0 || h.WriteTimeout > 0) {
			conn = &tcpRWTimeoutConn{
				TCPConn:      tcpConn,
				readTimeout:  time.Duration(h.ReadTimeout),
				writeTimeout: time.Duration(h.WriteTimeout),
				logger:       caddyCtx.Logger(),
			}
		}

		return conn, nil
	}

	// negotiate any HTTP/SOCKS proxy for the HTTP transport
	var proxy func(*http.Request) (*url.URL, error)
	if h.ForwardProxyURL != "" {
		pUrl, err := url.Parse(h.ForwardProxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse transport proxy url: %v", err)
		}
		caddyCtx.Logger().Info("setting transport proxy url", zap.String("url", h.ForwardProxyURL))
		proxy = http.ProxyURL(pUrl)
	} else {
		proxy = http.ProxyFromEnvironment
	}

	rt := &http.Transport{
		Proxy:                  proxy,
		DialContext:            dialContext,
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
		rt.TLSClientConfig, err = h.TLS.MakeTLSClientConfig(caddyCtx)
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

	// The proxy protocol header can only be sent once right after opening the connection.
	// So single connection must not be used for multiple requests, which can potentially
	// come from different clients.
	if !rt.DisableKeepAlives && h.ProxyProtocol != "" {
		caddyCtx.Logger().Warn("disabling keepalives, they are incompatible with using PROXY protocol")
		rt.DisableKeepAlives = true
	}

	if h.Compression != nil {
		rt.DisableCompression = !*h.Compression
	}

	if slices.Contains(h.Versions, "2") {
		if err := http2.ConfigureTransport(rt); err != nil {
			return nil, err
		}
	}

	// configure HTTP/3 transport if enabled; however, this does not
	// automatically fall back to lower versions like most web browsers
	// do (that'd add latency and complexity, besides, we expect that
	// site owners  control the backends), so it must be exclusive
	if len(h.Versions) == 1 && h.Versions[0] == "3" {
		h.h3Transport = new(http3.Transport)
		if h.TLS != nil {
			var err error
			h.h3Transport.TLSClientConfig, err = h.TLS.MakeTLSClientConfig(caddyCtx)
			if err != nil {
				return nil, fmt.Errorf("making TLS client config for HTTP/3 transport: %v", err)
			}
		}
	} else if len(h.Versions) > 1 && slices.Contains(h.Versions, "3") {
		return nil, fmt.Errorf("if HTTP/3 is enabled to the upstream, no other HTTP versions are supported")
	}

	// if h2c is enabled, configure its transport (std lib http.Transport
	// does not "HTTP/2 over cleartext TCP")
	if slices.Contains(h.Versions, "h2c") {
		// crafting our own http2.Transport doesn't allow us to utilize
		// most of the customizations/preferences on the http.Transport,
		// because, for some reason, only http2.ConfigureTransport()
		// is allowed to set the unexported field that refers to a base
		// http.Transport config; oh well
		h2t := &http2.Transport{
			// kind of a hack, but for plaintext/H2C requests, pretend to dial TLS
			DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
				return dialContext(ctx, network, address)
			},
			AllowHTTP: true,
		}
		if h.Compression != nil {
			h2t.DisableCompression = !*h.Compression
		}
		h.h2cTransport = h2t
	}

	return rt, nil
}

// replaceTLSServername checks TLS servername to see if it needs replacing
// if it does need replacing, it creates a new cloned HTTPTransport object to avoid any races
// and does the replacing of the TLS servername on that and returns the new object
// if no replacement is necessary it returns the original
func (h *HTTPTransport) replaceTLSServername(repl *caddy.Replacer) *HTTPTransport {
	// check whether we have TLS and need to replace the servername in the TLSClientConfig
	if h.TLSEnabled() && strings.Contains(h.TLS.ServerName, "{") {
		// make a new h, "copy" the parts we don't need to touch, add a new *tls.Config and replace servername
		newtransport := &HTTPTransport{
			Resolver:              h.Resolver,
			TLS:                   h.TLS,
			KeepAlive:             h.KeepAlive,
			Compression:           h.Compression,
			MaxConnsPerHost:       h.MaxConnsPerHost,
			DialTimeout:           h.DialTimeout,
			FallbackDelay:         h.FallbackDelay,
			ResponseHeaderTimeout: h.ResponseHeaderTimeout,
			ExpectContinueTimeout: h.ExpectContinueTimeout,
			MaxResponseHeaderSize: h.MaxResponseHeaderSize,
			WriteBufferSize:       h.WriteBufferSize,
			ReadBufferSize:        h.ReadBufferSize,
			Versions:              h.Versions,
			Transport:             h.Transport.Clone(),
			h2cTransport:          h.h2cTransport,
		}
		newtransport.Transport.TLSClientConfig.ServerName = repl.ReplaceAll(newtransport.Transport.TLSClientConfig.ServerName, "")
		return newtransport
	}

	return h
}

// RoundTrip implements http.RoundTripper.
func (h *HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Try to replace TLS servername if needed
	repl := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	transport := h.replaceTLSServername(repl)

	transport.SetScheme(req)

	// use HTTP/3 if enabled (TODO: This is EXPERIMENTAL)
	if h.h3Transport != nil {
		return h.h3Transport.RoundTrip(req)
	}

	// if H2C ("HTTP/2 over cleartext") is enabled and the upstream request is
	// HTTP without TLS, use the alternate H2C-capable transport instead
	if req.URL.Scheme == "http" && h.h2cTransport != nil {
		// There is no dedicated DisableKeepAlives field in *http2.Transport.
		// This is an alternative way to disable keep-alive.
		req.Close = h.Transport.DisableKeepAlives
		return h.h2cTransport.RoundTrip(req)
	}

	return transport.Transport.RoundTrip(req)
}

// SetScheme ensures that the outbound request req
// has the scheme set in its URL; the underlying
// http.Transport requires a scheme to be set.
//
// This method may be used by other transport modules
// that wrap/use this one.
func (h *HTTPTransport) SetScheme(req *http.Request) {
	if req.URL.Scheme != "" {
		return
	}
	if h.shouldUseTLS(req) {
		req.URL.Scheme = "https"
	} else {
		req.URL.Scheme = "http"
	}
}

// shouldUseTLS returns true if TLS should be used for req.
func (h *HTTPTransport) shouldUseTLS(req *http.Request) bool {
	if h.TLS == nil {
		return false
	}

	port := req.URL.Port()
	for i := range h.TLS.ExceptPorts {
		if h.TLS.ExceptPorts[i] == port {
			return false
		}
	}

	return true
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
	// Certificate authority module which provides the certificate pool of trusted certificates
	CARaw json.RawMessage `json:"ca,omitempty" caddy:"namespace=tls.ca_pool.source inline_key=provider"`

	// Deprecated: Use the `ca` field with the `tls.ca_pool.source.inline` module instead.
	// Optional list of base64-encoded DER-encoded CA certificates to trust.
	RootCAPool []string `json:"root_ca_pool,omitempty"`

	// Deprecated: Use the `ca` field with the `tls.ca_pool.source.file` module instead.
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

	// The duration to allow a TLS handshake to a server. Default: No timeout.
	HandshakeTimeout caddy.Duration `json:"handshake_timeout,omitempty"`

	// The server name used when verifying the certificate received in the TLS
	// handshake. By default, this will use the upstream address' host part.
	// You only need to override this if your upstream address does not match the
	// certificate the upstream is likely to use. For example if the upstream
	// address is an IP address, then you would need to configure this to the
	// hostname being served by the upstream server. Currently, this does not
	// support placeholders because the TLS config is not provisioned on each
	// connection, so a static value must be used.
	ServerName string `json:"server_name,omitempty"`

	// TLS renegotiation level. TLS renegotiation is the act of performing
	// subsequent handshakes on a connection after the first.
	// The level can be:
	//  - "never": (the default) disables renegotiation.
	//  - "once": allows a remote server to request renegotiation once per connection.
	//  - "freely": allows a remote server to repeatedly request renegotiation.
	Renegotiation string `json:"renegotiation,omitempty"`

	// Skip TLS ports specifies a list of upstream ports on which TLS should not be
	// attempted even if it is configured. Handy when using dynamic upstreams that
	// return HTTP and HTTPS endpoints too.
	// When specified, TLS will automatically be configured on the transport.
	// The value can be a list of any valid tcp port numbers, default empty.
	ExceptPorts []string `json:"except_ports,omitempty"`

	// The list of elliptic curves to support. Caddy's
	// defaults are modern and secure.
	Curves []string `json:"curves,omitempty"`
}

// MakeTLSClientConfig returns a tls.Config usable by a client to a backend.
// If there is no custom TLS configuration, a nil config may be returned.
func (t *TLSConfig) MakeTLSClientConfig(ctx caddy.Context) (*tls.Config, error) {
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
			certs := caddytls.AllMatchingCertificates(t.ClientCertificateAutomate)
			var err error
			for _, cert := range certs {
				certCertificate := cert.Certificate // avoid taking address of iteration variable (gosec warning)
				err = cri.SupportsCertificate(&certCertificate)
				if err == nil {
					return &cert.Certificate, nil
				}
			}
			if err == nil {
				err = fmt.Errorf("no client certificate found for automate name: %s", t.ClientCertificateAutomate)
			}
			return nil, err
		}
	}

	// trusted root CAs
	if len(t.RootCAPool) > 0 || len(t.RootCAPEMFiles) > 0 {
		ctx.Logger().Warn("root_ca_pool and root_ca_pem_files are deprecated. Use one of the tls.ca_pool.source modules instead")
		rootPool := x509.NewCertPool()
		for _, encodedCACert := range t.RootCAPool {
			caCert, err := decodeBase64DERCert(encodedCACert)
			if err != nil {
				return nil, fmt.Errorf("parsing CA certificate: %v", err)
			}
			rootPool.AddCert(caCert)
		}
		for _, pemFile := range t.RootCAPEMFiles {
			pemData, err := os.ReadFile(pemFile)
			if err != nil {
				return nil, fmt.Errorf("failed reading ca cert: %v", err)
			}
			rootPool.AppendCertsFromPEM(pemData)
		}
		cfg.RootCAs = rootPool
	}

	if t.CARaw != nil {
		if len(t.RootCAPool) > 0 || len(t.RootCAPEMFiles) > 0 {
			return nil, fmt.Errorf("conflicting config for Root CA pool")
		}
		caRaw, err := ctx.LoadModule(t, "CARaw")
		if err != nil {
			return nil, fmt.Errorf("failed to load ca module: %v", err)
		}
		ca, ok := caRaw.(caddytls.CA)
		if !ok {
			return nil, fmt.Errorf("CA module '%s' is not a certificate pool provider", ca)
		}
		cfg.RootCAs = ca.CertPool()
	}

	// Renegotiation
	switch t.Renegotiation {
	case "never", "":
		cfg.Renegotiation = tls.RenegotiateNever
	case "once":
		cfg.Renegotiation = tls.RenegotiateOnceAsClient
	case "freely":
		cfg.Renegotiation = tls.RenegotiateFreelyAsClient
	default:
		return nil, fmt.Errorf("invalid TLS renegotiation level: %v", t.Renegotiation)
	}

	// override for the server name used verify the TLS handshake
	cfg.ServerName = t.ServerName

	// throw all security out the window
	cfg.InsecureSkipVerify = t.InsecureSkipVerify

	curvesAdded := make(map[tls.CurveID]struct{})
	for _, curveName := range t.Curves {
		curveID := caddytls.SupportedCurves[curveName]
		if _, ok := curvesAdded[curveID]; !ok {
			curvesAdded[curveID] = struct{}{}
			cfg.CurvePreferences = append(cfg.CurvePreferences, curveID)
		}
	}

	// only return a config if it's not empty
	if reflect.DeepEqual(cfg, new(tls.Config)) {
		return nil, nil
	}

	return cfg, nil
}

// KeepAlive holds configuration pertaining to HTTP Keep-Alive.
type KeepAlive struct {
	// Whether HTTP Keep-Alive is enabled. Default: `true`
	Enabled *bool `json:"enabled,omitempty"`

	// How often to probe for liveness. Default: `30s`.
	ProbeInterval caddy.Duration `json:"probe_interval,omitempty"`

	// Maximum number of idle connections. Default: `0`, which means no limit.
	MaxIdleConns int `json:"max_idle_conns,omitempty"`

	// Maximum number of idle connections per host. Default: `32`.
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`

	// How long connections should be kept alive when idle. Default: `2m`.
	IdleConnTimeout caddy.Duration `json:"idle_timeout,omitempty"`
}

// tcpRWTimeoutConn enforces read/write timeouts for a TCP connection.
// If it fails to set deadlines, the error is logged but does not abort
// the read/write attempt (ignoring the error is consistent with what
// the standard library does: https://github.com/golang/go/blob/c5da4fb7ac5cb7434b41fc9a1df3bee66c7f1a4d/src/net/http/server.go#L981-L986)
type tcpRWTimeoutConn struct {
	*net.TCPConn
	readTimeout, writeTimeout time.Duration
	logger                    *zap.Logger
}

func (c *tcpRWTimeoutConn) Read(b []byte) (int, error) {
	if c.readTimeout > 0 {
		err := c.TCPConn.SetReadDeadline(time.Now().Add(c.readTimeout))
		if err != nil {
			if ce := c.logger.Check(zapcore.ErrorLevel, "failed to set read deadline"); ce != nil {
				ce.Write(zap.Error(err))
			}
		}
	}
	return c.TCPConn.Read(b)
}

func (c *tcpRWTimeoutConn) Write(b []byte) (int, error) {
	if c.writeTimeout > 0 {
		err := c.TCPConn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
		if err != nil {
			if ce := c.logger.Check(zapcore.ErrorLevel, "failed to set write deadline"); ce != nil {
				ce.Write(zap.Error(err))
			}
		}
	}
	return c.TCPConn.Write(b)
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

// Interface guards
var (
	_ caddy.Provisioner  = (*HTTPTransport)(nil)
	_ http.RoundTripper  = (*HTTPTransport)(nil)
	_ caddy.CleanerUpper = (*HTTPTransport)(nil)
	_ TLSTransport       = (*HTTPTransport)(nil)
)
