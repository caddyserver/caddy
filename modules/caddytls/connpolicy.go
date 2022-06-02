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
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/acmez"
)

// ConnectionPolicies govern the establishment of TLS connections. It is
// an ordered group of connection policies; the first matching policy will
// be used to configure TLS connections at handshake-time.
type ConnectionPolicies []*ConnectionPolicy

// Provision sets up each connection policy. It should be called
// during the Validate() phase, after the TLS app (if any) is
// already set up.
func (cp ConnectionPolicies) Provision(ctx caddy.Context) error {
	for i, pol := range cp {
		// matchers
		mods, err := ctx.LoadModule(pol, "MatchersRaw")
		if err != nil {
			return fmt.Errorf("loading handshake matchers: %v", err)
		}
		for _, modIface := range mods.(map[string]interface{}) {
			cp[i].matchers = append(cp[i].matchers, modIface.(ConnectionMatcher))
		}

		// enable HTTP/2 by default
		if len(pol.ALPN) == 0 {
			pol.ALPN = append(pol.ALPN, defaultALPN...)
		}

		// pre-build standard TLS config so we don't have to at handshake-time
		err = pol.buildStandardTLSConfig(ctx)
		if err != nil {
			return fmt.Errorf("connection policy %d: building standard TLS config: %s", i, err)
		}

		if pol.ClientAuthentication != nil && len(pol.ClientAuthentication.ValidatorsRaw) > 0 {
				clientCertValidations, err := ctx.LoadModule(pol.ClientAuthentication, "ValidatorsRaw")
				if err != nil {
					return fmt.Errorf("loading client cert validators: %v", err)
				}
				for _, validator := range clientCertValidations.([]interface{}) {
					cp[i].ClientAuthentication.validators = append(cp[i].ClientAuthentication.validators, validator.(ClientCertValidator))
				}
			}
		}
	}

	return nil
}

// TLSConfig returns a standard-lib-compatible TLS configuration which
// selects the first matching policy based on the ClientHello.
func (cp ConnectionPolicies) TLSConfig(_ caddy.Context) *tls.Config {
	// using ServerName to match policies is extremely common, especially in configs
	// with lots and lots of different policies; we can fast-track those by indexing
	// them by SNI, so we don't have to iterate potentially thousands of policies
	// (TODO: this map does not account for wildcards, see if this is a problem in practice? look for reports of high connection latency with wildcard certs but low latency for non-wildcards in multi-thousand-cert deployments)
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
		MinVersion: tls.VersionTLS12,
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
	}
}

// ConnectionPolicy specifies the logic for handling a TLS handshake.
// An empty policy is valid; safe and sensible defaults will be used.
type ConnectionPolicy struct {
	// How to match this policy with a TLS ClientHello. If
	// this policy is the first to match, it will be used.
	MatchersRaw caddy.ModuleMap `json:"match,omitempty" caddy:"namespace=tls.handshake_match"`

	// How to choose a certificate if more than one matched
	// the given ServerName (SNI) value.
	CertSelection *CustomCertSelectionPolicy `json:"certificate_selection,omitempty"`

	// The list of cipher suites to support. Caddy's
	// defaults are modern and secure.
	CipherSuites []string `json:"cipher_suites,omitempty"`

	// The list of elliptic curves to support. Caddy's
	// defaults are modern and secure.
	Curves []string `json:"curves,omitempty"`

	// Protocols to use for Application-Layer Protocol
	// Negotiation (ALPN) during the handshake.
	ALPN []string `json:"alpn,omitempty"`

	// Minimum TLS protocol version to allow. Default: `tls1.2`
	ProtocolMin string `json:"protocol_min,omitempty"`

	// Maximum TLS protocol version to allow. Default: `tls1.3`
	ProtocolMax string `json:"protocol_max,omitempty"`

	// Enables and configures TLS client authentication.
	ClientAuthentication *ClientAuthentication `json:"client_authentication,omitempty"`

	// DefaultSNI becomes the ServerName in a ClientHello if there
	// is no policy configured for the empty SNI value.
	DefaultSNI string `json:"default_sni,omitempty"`

	matchers     []ConnectionMatcher
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
			// TODO: I don't love how this works: we pre-build certmagic configs
			// so that handshakes are faster. Unfortunately, certmagic configs are
			// comprised of settings from both a TLS connection policy and a TLS
			// automation policy. The only two fields (as of March 2020; v2 beta 17)
			// of a certmagic config that come from the TLS connection policy are
			// CertSelection and DefaultServerName, so an automation policy is what
			// builds the base certmagic config. Since the pre-built config is
			// shared, I don't think we can change any of its fields per-handshake,
			// hence the awkward shallow copy (dereference) here and the subsequent
			// changing of some of its fields. I'm worried this dereference allocates
			// more at handshake-time, but I don't know how to practically pre-build
			// a certmagic config for each combination of conn policy + automation policy...
			cfg := *tlsApp.getConfigForName(hello.ServerName)
			if p.CertSelection != nil {
				// you would think we could just set this whether or not
				// p.CertSelection is nil, but that leads to panics if
				// it is, because cfg.CertSelection is an interface,
				// so it will have a non-nil value even if the actual
				// value underlying it is nil (sigh)
				cfg.CertSelection = p.CertSelection
			}
			cfg.DefaultServerName = p.DefaultSNI
			return cfg.GetCertificate(hello)
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
			// do cleanup when the context is canceled because,
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
		csID := CipherSuiteID(csName)
		if csID == 0 {
			return fmt.Errorf("unsupported cipher suite: %s", csName)
		}
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
		if a == acmez.ACMETLS1Protocol {
			alpnFound = true
			break
		}
	}
	if !alpnFound {
		cfg.NextProtos = append(cfg.NextProtos, acmez.ACMETLS1Protocol)
	}

	// min and max protocol versions
	if (p.ProtocolMin != "" && p.ProtocolMax != "") && p.ProtocolMin > p.ProtocolMax {
		return fmt.Errorf("protocol min (%x) cannot be greater than protocol max (%x)", p.ProtocolMin, p.ProtocolMax)
	}
	if p.ProtocolMin != "" {
		cfg.MinVersion = SupportedProtocols[p.ProtocolMin]
	}
	if p.ProtocolMax != "" {
		cfg.MaxVersion = SupportedProtocols[p.ProtocolMax]
	}

	// client authentication
	if p.ClientAuthentication != nil {
		err := p.ClientAuthentication.ConfigureTLSConfig(cfg)
		if err != nil {
			return fmt.Errorf("configuring TLS client authentication: %v", err)
		}
	}

	setDefaultTLSParams(cfg)

	p.stdTLSConfig = cfg

	return nil
}

// SettingsEmpty returns true if p's settings (fields
// except the matchers) are all empty/unset.
func (p ConnectionPolicy) SettingsEmpty() bool {
	return p.CertSelection == nil &&
		p.CipherSuites == nil &&
		p.Curves == nil &&
		p.ALPN == nil &&
		p.ProtocolMin == "" &&
		p.ProtocolMax == "" &&
		p.ClientAuthentication == nil &&
		p.DefaultSNI == ""
}

// ClientAuthentication configures TLS client auth.
type ClientAuthentication struct {
	// A list of base64 DER-encoded CA certificates
	// against which to validate client certificates.
	// Client certs which are not signed by any of
	// these CAs will be rejected.
	TrustedCACerts []string `json:"trusted_ca_certs,omitempty"`

	// TrustedCACertPEMFiles is a list of PEM file names
	// from which to load certificates of trusted CAs.
	// Client certificates which are not signed by any of
	// these CA certificates will be rejected.
	TrustedCACertPEMFiles []string `json:"trusted_ca_certs_pem_files,omitempty"`

	// A list of base64 DER-encoded client leaf certs
	// to accept. If this list is not empty, client certs
	// which are not in this list will be rejected.
	TrustedLeafCerts []string `json:"trusted_leaf_certs,omitempty"`

	// A list of client certificate validators, for additional
	// verification. These can perform custom checks, like ensuring
	// the certificate is not revoked.
	ValidatorsRaw []json.RawMessage `json:"validators,omitempty" caddy:"namespace=tls.client_auth inline_key=validator"`

	validators []ClientCertValidator

	// The mode for authenticating the client. Allowed values are:
	//
	// Mode | Description
	// -----|---------------
	// `request` | Ask clients for a certificate, but allow even if there isn't one; do not verify it
	// `require` | Require clients to present a certificate, but do not verify it
	// `verify_if_given` | Ask clients for a certificate; allow even if there isn't one, but verify it if there is
	// `require_and_verify` | Require clients to present a valid certificate that is verified
	//
	// The default mode is `require_and_verify` if any
	// TrustedCACerts or TrustedCACertPEMFiles or TrustedLeafCerts
	// are provided; otherwise, the default mode is `require`.
	Mode string `json:"mode,omitempty"`

	existingVerifyPeerCert func([][]byte, [][]*x509.Certificate) error
}

// Active returns true if clientauth has an actionable configuration.
func (clientauth ClientAuthentication) Active() bool {
	return len(clientauth.TrustedCACerts) > 0 ||
		len(clientauth.TrustedCACertPEMFiles) > 0 ||
		len(clientauth.TrustedLeafCerts) > 0 ||
		len(clientauth.Mode) > 0
}

// ConfigureTLSConfig sets up cfg to enforce clientauth's configuration.
func (clientauth *ClientAuthentication) ConfigureTLSConfig(cfg *tls.Config) error {
	// if there's no actionable client auth, simply disable it
	if !clientauth.Active() {
		cfg.ClientAuth = tls.NoClientCert
		return nil
	}

	// enforce desired mode of client authentication
	if len(clientauth.Mode) > 0 {
		switch clientauth.Mode {
		case "request":
			cfg.ClientAuth = tls.RequestClientCert
		case "require":
			cfg.ClientAuth = tls.RequireAnyClientCert
		case "verify_if_given":
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		case "require_and_verify":
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		default:
			return fmt.Errorf("client auth mode not recognized: %s", clientauth.Mode)
		}
	} else {
		// otherwise, set a safe default mode
		if len(clientauth.TrustedCACerts) > 0 ||
			len(clientauth.TrustedCACertPEMFiles) > 0 ||
			len(clientauth.TrustedLeafCerts) > 0 {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.RequireAnyClientCert
		}
	}

	// enforce CA verification by adding CA certs to the ClientCAs pool
	if len(clientauth.TrustedCACerts) > 0 || len(clientauth.TrustedCACertPEMFiles) > 0 {
		caPool := x509.NewCertPool()
		for _, clientCAString := range clientauth.TrustedCACerts {
			clientCA, err := decodeBase64DERCert(clientCAString)
			if err != nil {
				return fmt.Errorf("parsing certificate: %v", err)
			}
			caPool.AddCert(clientCA)
		}
		for _, pemFile := range clientauth.TrustedCACertPEMFiles {
			pemContents, err := os.ReadFile(pemFile)
			if err != nil {
				return fmt.Errorf("reading %s: %v", pemFile, err)
			}
			caPool.AppendCertsFromPEM(pemContents)
		}
		cfg.ClientCAs = caPool
	}

	// enforce leaf verification by adding a validator
	if len(clientauth.TrustedLeafCerts) > 0 {
		var trustedLeafCerts []*x509.Certificate
		for _, clientCertString := range clientauth.TrustedLeafCerts {
			clientCert, err := decodeBase64DERCert(clientCertString)
			if err != nil {
				return fmt.Errorf("parsing certificate: %v", err)
			}
			trustedLeafCerts = append(trustedLeafCerts, clientCert)
		}
		clientauth.validators = append(clientauth.validators, LeafCertClientAuth{TrustedLeafCerts: trustedLeafCerts})
	}

	// if a custom verification function already exists, wrap it
	clientauth.existingVerifyPeerCert = cfg.VerifyPeerCertificate
	cfg.VerifyPeerCertificate = clientauth.verifyPeerCertificate
	return nil
}

// verifyPeerCertificate is for use as a tls.Config.VerifyPeerCertificate
// callback to do custom client certificate verification. It is intended
// for installation only by clientauth.ConfigureTLSConfig().
func (clientauth *ClientAuthentication) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// first use any pre-existing custom verification function
	if clientauth.existingVerifyPeerCert != nil {
		err := clientauth.existingVerifyPeerCert(rawCerts, verifiedChains)
		if err != nil {
			return err
		}
	}
	for _, validator := range clientauth.validators {
		err := validator.VerifyClientCertificate(rawCerts, verifiedChains)
		if err != nil {
			return err
		}
	}
	return nil
}

// decodeBase64DERCert base64-decodes, then DER-decodes, certStr.
func decodeBase64DERCert(certStr string) (*x509.Certificate, error) {
	derBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, err
	}
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

// LeafVerificationValidator implements custom client certificate verification.
// It is intended for installation only by clientauth.ConfigureTLSConfig().
type LeafCertClientAuth struct {
	TrustedLeafCerts []*x509.Certificate
}

func (l LeafCertClientAuth) VerifyClientCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	remoteLeafCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("can't parse the given certificate: %s", err.Error())
	}

	for _, trustedLeafCert := range l.TrustedLeafCerts {
		if remoteLeafCert.Equal(trustedLeafCert) {
			return nil
		}
	}

	return fmt.Errorf("client leaf certificate failed validation")
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

// ClientCertValidator is a type which validates client certificates.
// It is called during verifyPeerCertificate in the TLS handshake.
type ClientCertificateValidator interface {
	VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

var defaultALPN = []string{"h2", "http/1.1"}
