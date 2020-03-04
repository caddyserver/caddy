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

package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
	"github.com/mholt/certmagic"
)

// ConnectionPolicies is an ordered group of connection policies;
// the first matching policy will be used to configure TLS
// connections at handshake-time.
type ConnectionPolicies []*ConnectionPolicy

// TLSConfig converts the group of policies to a standard-lib-compatible
// TLS configuration which selects the first matching policy based on
// the ClientHello.
func (cp ConnectionPolicies) TLSConfig(ctx caddy.Context) (*tls.Config, error) {
	// set up each of the connection policies
	for i, pol := range cp {
		// matchers
		for modName, rawMsg := range pol.Matchers {
			val, err := ctx.LoadModule("tls.handshake_match."+modName, rawMsg)
			if err != nil {
				return nil, fmt.Errorf("loading handshake matcher module '%s': %s", modName, err)
			}
			cp[i].matchers = append(cp[i].matchers, val.(ConnectionMatcher))
		}
		cp[i].Matchers = nil // allow GC to deallocate

		// certificate selector
		if pol.CertSelection != nil {
			val, err := ctx.LoadModuleInline("policy", "tls.certificate_selection", pol.CertSelection)
			if err != nil {
				return nil, fmt.Errorf("loading certificate selection module: %s", err)
			}
			cp[i].certSelector = val.(certmagic.CertificateSelector)
			cp[i].CertSelection = nil // allow GC to deallocate
		}
	}

	// pre-build standard TLS configs so we don't have to at handshake-time
	for i := range cp {
		err := cp[i].buildStandardTLSConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("connection policy %d: building standard TLS config: %s", i, err)
		}
	}

	// using ServerName to match policies is extremely common, especially in configs
	// with lots and lots of different policies; we can fast-track those by indexing
	// them by SNI, so we don't have to iterate potentially thousands of policies
	indexedBySNI := make(map[string]ConnectionPolicies)
	if len(cp) > 30 {
		for _, p := range cp {
			for _, m := range p.matchers {
				if sni, ok := m.(MatchServerName); ok {
					for _, sniName := range sni {
						indexedBySNI[sniName] = append(indexedBySNI[sniName], p)
					}
				}
			}
		}
	}

	return &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// filter policies by SNI first, if possible, to speed things up
			// when there may be lots of policies
			possiblePolicies := cp
			if indexedPolicies, ok := indexedBySNI[hello.ServerName]; ok {
				possiblePolicies = indexedPolicies
			}

		policyLoop:
			for _, pol := range possiblePolicies {
				for _, matcher := range pol.matchers {
					if !matcher.Match(hello) {
						continue policyLoop
					}
				}
				return pol.stdTLSConfig, nil
			}

			return nil, fmt.Errorf("no server TLS configuration available for ClientHello: %+v", hello)
		},
	}, nil
}

// ConnectionPolicy specifies the logic for handling a TLS handshake.
type ConnectionPolicy struct {
	Matchers      map[string]json.RawMessage `json:"match,omitempty"`
	CertSelection json.RawMessage            `json:"certificate_selection,omitempty"`

	CipherSuites         []string              `json:"cipher_suites,omitempty"`
	Curves               []string              `json:"curves,omitempty"`
	ALPN                 []string              `json:"alpn,omitempty"`
	ProtocolMin          string                `json:"protocol_min,omitempty"`
	ProtocolMax          string                `json:"protocol_max,omitempty"`
	ClientAuthentication *ClientAuthentication `json:"client_authentication,omitempty"`

	matchers     []ConnectionMatcher
	certSelector certmagic.CertificateSelector

	stdTLSConfig *tls.Config
}

func (p *ConnectionPolicy) buildStandardTLSConfig(ctx caddy.Context) error {
	tlsAppIface, err := ctx.App("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}
	tlsApp := tlsAppIface.(*TLS)

	// fill in some "easy" default values, but for other values
	// (such as slices), we should ensure that they start empty
	// so the user-provided config can fill them in; then we will
	// fill in a default config at the end if they are still unset
	cfg := &tls.Config{
		NextProtos:               p.ALPN,
		PreferServerCipherSuites: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cfgTpl, err := tlsApp.getConfigForName(hello.ServerName)
			if err != nil {
				return nil, fmt.Errorf("getting config for name %s: %v", hello.ServerName, err)
			}
			newCfg := certmagic.New(tlsApp.certCache, cfgTpl)
			if p.certSelector != nil {
				newCfg.CertSelection = p.certSelector
			}
			return newCfg.GetCertificate(hello)
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	// session tickets support
	if tlsApp.SessionTickets != nil {
		cfg.SessionTicketsDisabled = tlsApp.SessionTickets.Disabled

		// session ticket key rotation
		tlsApp.SessionTickets.register(cfg)
		ctx.OnCancel(func() {
			// do cleanup when the context is cancelled because,
			// though unlikely, it is possible that a context
			// needing a TLS server config could exist for less
			// than the lifetime of the whole app
			tlsApp.SessionTickets.unregister(cfg)
		})
	}

	// TODO: Clean up session ticket active locks in storage if app (or process) is being closed!

	// add all the cipher suites in order, without duplicates
	cipherSuitesAdded := make(map[uint16]struct{})
	for _, csName := range p.CipherSuites {
		csID := SupportedCipherSuites[csName]
		if _, ok := cipherSuitesAdded[csID]; !ok {
			cipherSuitesAdded[csID] = struct{}{}
			cfg.CipherSuites = append(cfg.CipherSuites, csID)
		}
	}

	// add all the curve preferences in order, without duplicates
	curvesAdded := make(map[tls.CurveID]struct{})
	for _, curveName := range p.Curves {
		curveID := SupportedCurves[curveName]
		if _, ok := curvesAdded[curveID]; !ok {
			curvesAdded[curveID] = struct{}{}
			cfg.CurvePreferences = append(cfg.CurvePreferences, curveID)
		}
	}

	// ensure ALPN includes the ACME TLS-ALPN protocol
	var alpnFound bool
	for _, a := range p.ALPN {
		if a == tlsalpn01.ACMETLS1Protocol {
			alpnFound = true
			break
		}
	}
	if !alpnFound {
		cfg.NextProtos = append(cfg.NextProtos, tlsalpn01.ACMETLS1Protocol)
	}

	// min and max protocol versions
	if p.ProtocolMin != "" {
		cfg.MinVersion = SupportedProtocols[p.ProtocolMin]
	}
	if p.ProtocolMax != "" {
		cfg.MaxVersion = SupportedProtocols[p.ProtocolMax]
	}
	if p.ProtocolMin > p.ProtocolMax {
		return fmt.Errorf("protocol min (%x) cannot be greater than protocol max (%x)", p.ProtocolMin, p.ProtocolMax)
	}

	// client authentication
	if p.ClientAuthentication != nil {
		err := p.ClientAuthentication.ConfigureTLSConfig(cfg)
		if err != nil {
			return fmt.Errorf("configuring TLS client authentication: %v", err)
		}
	}

	// TODO: other fields

	setDefaultTLSParams(cfg)

	p.stdTLSConfig = cfg

	return nil
}

// ClientAuthentication configures TLS client auth.
type ClientAuthentication struct {
	// A list of base64 DER-encoded CA certificates
	// against which to validate client certificates.
	// Client certs which are not signed by any of
	// these CAs will be rejected.
	TrustedCACerts []string `json:"trusted_ca_certs,omitempty"`

	// A list of base64 DER-encoded client leaf certs
	// to accept. If this list is not empty, client certs
	// which are not in this list will be rejected.
	TrustedLeafCerts []string `json:"trusted_leaf_certs,omitempty"`

	// The mode of the client authentication - the allowed values are
	// 'request'		- A client certificate is retrieved if available (but is not otherwise verified), if no client cert is presented this is also ok
	// 'require'		- A client certificate must be presented (but is not otherwise verified)
	// 'verify_if_given'	- Verify the presented client certificate if a client cert is presented, if no client cert is presented this is also ok
	// 'require_and_verify'	- Verify the presented client certificate. A client certificate must be presented
	Mode string `json:"mode,omitempty"`

	// state established with the last call to ConfigureTLSConfig
	trustedLeafCerts       []*x509.Certificate
	existingVerifyPeerCert func([][]byte, [][]*x509.Certificate) error
}

// Active returns true if clientauth has an actionable configuration.
func (clientauth ClientAuthentication) Active() bool {
	return len(clientauth.TrustedCACerts) > 0 || len(clientauth.TrustedLeafCerts) > 0 || len(clientauth.Mode) > 0
}

// ConfigureTLSConfig sets up cfg to enforce clientauth's configuration.
func (clientauth *ClientAuthentication) ConfigureTLSConfig(cfg *tls.Config) error {
	// if there's no actionable client auth, simply disable it
	if !clientauth.Active() {
		cfg.ClientAuth = tls.NoClientCert
		return nil
	}

	// Setup the Client auth according to the possibilites for TLS client auth 
	if (len(clientauth.Mode) > 0) {
		switch clientauth.Mode {
			case "request": {
				cfg.ClientAuth = tls.RequestClientCert
			}
			case "require": {
				cfg.ClientAuth = tls.RequireAnyClientCert
			}
			case "verify_if_given": {
				cfg.ClientAuth = tls.VerifyClientCertIfGiven
			}
			case "require_and_verify": {
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
			}
			default: {
				return fmt.Errorf("client auth mode %s not allowed", clientauth.Mode)
			}
		}
	} else {
		// otherwise, at least require any client certificate
		cfg.ClientAuth = tls.RequireAnyClientCert
	}

	// enforce CA verification by adding CA certs to the ClientCAs pool
	if len(clientauth.TrustedCACerts) > 0 {
		caPool := x509.NewCertPool()
		for _, clientCAString := range clientauth.TrustedCACerts {
			clientCA, err := decodeBase64DERCert(clientCAString)
			if err != nil {
				return fmt.Errorf("parsing certificate: %v", err)
			}
			caPool.AddCert(clientCA)
		}
		cfg.ClientCAs = caPool

		// now ensure the standard lib will verify client certificates
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// enforce leaf verification by writing our own verify function
	if len(clientauth.TrustedLeafCerts) > 0 {
		clientauth.trustedLeafCerts = []*x509.Certificate{}

		for _, clientCertString := range clientauth.TrustedLeafCerts {
			clientCert, err := decodeBase64DERCert(clientCertString)
			if err != nil {
				return fmt.Errorf("parsing certificate: %v", err)
			}
			clientauth.trustedLeafCerts = append(clientauth.trustedLeafCerts, clientCert)
		}

		// if a custom verification function already exists, wrap it
		clientauth.existingVerifyPeerCert = cfg.VerifyPeerCertificate

		cfg.VerifyPeerCertificate = clientauth.verifyPeerCertificate
	}

	return nil
}

// verifyPeerCertificate is for use as a tls.Config.VerifyPeerCertificate
// callback to do custom client certificate verification. It is intended
// for installation only by clientauth.ConfigureTLSConfig().
func (clientauth ClientAuthentication) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// first use any pre-existing custom verification function
	if clientauth.existingVerifyPeerCert != nil {
		err := clientauth.existingVerifyPeerCert(rawCerts, verifiedChains)
		if err != nil {
			return err
		}
	}

	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	remoteLeafCert, err := x509.ParseCertificate(rawCerts[len(rawCerts)-1])
	if err != nil {
		return fmt.Errorf("can't parse the given certificate: %s", err.Error())
	}

	for _, trustedLeafCert := range clientauth.trustedLeafCerts {
		if remoteLeafCert.Equal(trustedLeafCert) {
			return nil
		}
	}

	return fmt.Errorf("client leaf certificate failed validation")
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

// setDefaultTLSParams sets the default TLS cipher suites, protocol versions,
// and server preferences of cfg if they are not already set; it does not
// overwrite values, only fills in missing values.
func setDefaultTLSParams(cfg *tls.Config) {
	if len(cfg.CipherSuites) == 0 {
		cfg.CipherSuites = getOptimalDefaultCipherSuites()
	}

	// Not a cipher suite, but still important for mitigating protocol downgrade attacks
	// (prepend since having it at end breaks http2 due to non-h2-approved suites before it)
	cfg.CipherSuites = append([]uint16{tls.TLS_FALLBACK_SCSV}, cfg.CipherSuites...)

	if len(cfg.CurvePreferences) == 0 {
		cfg.CurvePreferences = defaultCurves
	}

	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	if cfg.MaxVersion == 0 {
		cfg.MaxVersion = tls.VersionTLS13
	}

	cfg.PreferServerCipherSuites = true
}

// PublicKeyAlgorithm is a JSON-unmarshalable wrapper type.
type PublicKeyAlgorithm x509.PublicKeyAlgorithm

// UnmarshalJSON satisfies json.Unmarshaler.
func (a *PublicKeyAlgorithm) UnmarshalJSON(b []byte) error {
	algoStr := strings.ToLower(strings.Trim(string(b), `"`))
	algo, ok := publicKeyAlgorithms[algoStr]
	if !ok {
		return fmt.Errorf("unrecognized public key algorithm: %s (expected one of %v)",
			algoStr, publicKeyAlgorithms)
	}
	*a = PublicKeyAlgorithm(algo)
	return nil
}

// ConnectionMatcher is a type which matches TLS handshakes.
type ConnectionMatcher interface {
	Match(*tls.ClientHelloInfo) bool
}
