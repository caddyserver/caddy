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
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/caddyserver/caddy/v2"
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

	TLS                   *TLSConfig     `json:"tls,omitempty"`
	KeepAlive             *KeepAlive     `json:"keep_alive,omitempty"`
	Compression           *bool          `json:"compression,omitempty"`
	MaxConnsPerHost       int            `json:"max_conns_per_host,omitempty"`
	DialTimeout           caddy.Duration `json:"dial_timeout,omitempty"`
	FallbackDelay         caddy.Duration `json:"dial_fallback_delay,omitempty"`
	ResponseHeaderTimeout caddy.Duration `json:"response_header_timeout,omitempty"`
	ExpectContinueTimeout caddy.Duration `json:"expect_continue_timeout,omitempty"`
	MaxResponseHeaderSize int64          `json:"max_response_header_size,omitempty"`
	WriteBufferSize       int            `json:"write_buffer_size,omitempty"`
	ReadBufferSize        int            `json:"read_buffer_size,omitempty"`
	Versions              []string       `json:"versions,omitempty"`

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
func (h *HTTPTransport) Provision(_ caddy.Context) error {
	if len(h.Versions) == 0 {
		h.Versions = []string{"1.1", "2"}
	}

	rt, err := h.newTransport()
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

func (h *HTTPTransport) newTransport() (*http.Transport, error) {
	dialer := &net.Dialer{
		Timeout:       time.Duration(h.DialTimeout),
		FallbackDelay: time.Duration(h.FallbackDelay),
		// TODO: Resolver
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
		rt.TLSClientConfig, err = h.TLS.MakeTLSClientConfig()
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
	h.setScheme(req)

	// if H2C ("HTTP/2 over cleartext") is enabled and this is an HTTP
	// request, use the alternate, H2C-capable transport instead
	if h.h2cTransport != nil && req.URL.Scheme == "http" {
		return h.h2cTransport.RoundTrip(req)
	}

	return h.RoundTrip(req)
}

// setScheme ensures that the outbound request req
// has the scheme set in its URL; the underlying
// http.Transport requires a scheme to be set.
func (h *HTTPTransport) setScheme(req *http.Request) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
		if h.TLS != nil {
			req.URL.Scheme = "https"
		}
	}
}

// Cleanup implements caddy.CleanerUpper and closes any idle connections.
func (h HTTPTransport) Cleanup() error {
	if h.Transport == nil {
		return nil
	}
	h.Transport.CloseIdleConnections()
	return nil
}

// TLSConfig holds configuration related to the
// TLS configuration for the transport/client.
type TLSConfig struct {
	RootCAPool []string `json:"root_ca_pool,omitempty"`
	// Added to the same pool as above, but brought in from files
	RootCAPEMFiles []string `json:"root_ca_pem_files,omitempty"`
	// TODO: Should the client cert+key config use caddytls.CertificateLoader modules?
	ClientCertificateFile    string         `json:"client_certificate_file,omitempty"`
	ClientCertificateKeyFile string         `json:"client_certificate_key_file,omitempty"`
	InsecureSkipVerify       bool           `json:"insecure_skip_verify,omitempty"`
	HandshakeTimeout         caddy.Duration `json:"handshake_timeout,omitempty"`
	ServerName               string         `json:"server_name,omitempty"`
}

// MakeTLSClientConfig returns a tls.Config usable by a client to a backend.
// If there is no custom TLS configuration, a nil config may be returned.
func (t TLSConfig) MakeTLSClientConfig() (*tls.Config, error) {
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

// KeepAlive holds configuration pertaining to HTTP Keep-Alive.
type KeepAlive struct {
	Enabled             *bool          `json:"enabled,omitempty"`
	ProbeInterval       caddy.Duration `json:"probe_interval,omitempty"`
	MaxIdleConns        int            `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost int            `json:"max_idle_conns_per_host,omitempty"`
	IdleConnTimeout     caddy.Duration `json:"idle_timeout,omitempty"` // how long should connections be kept alive when idle
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
)
