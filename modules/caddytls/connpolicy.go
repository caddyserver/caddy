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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mholt/acmez/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(LeafCertClientAuth{})
}

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
		for _, modIface := range mods.(map[string]any) {
			cp[i].matchers = append(cp[i].matchers, modIface.(ConnectionMatcher))
		}

		// enable HTTP/2 by default
		if pol.ALPN == nil {
			pol.ALPN = append(pol.ALPN, defaultALPN...)
		}

		// pre-build standard TLS config so we don't have to at handshake-time
		err = pol.buildStandardTLSConfig(ctx)
		if err != nil {
			return fmt.Errorf("connection policy %d: building standard TLS config: %s", i, err)
		}

		if pol.ClientAuthentication != nil && len(pol.ClientAuthentication.VerifiersRaw) > 0 {
			clientCertValidations, err := ctx.LoadModule(pol.ClientAuthentication, "VerifiersRaw")
			if err != nil {
				return fmt.Errorf("loading client cert verifiers: %v", err)
			}
			for _, validator := range clientCertValidations.([]any) {
				cp[i].ClientAuthentication.verifiers = append(cp[i].ClientAuthentication.verifiers, validator.(ClientCertificateVerifier))
			}
		}

		if len(pol.HandshakeContextRaw) > 0 {
			modIface, err := ctx.LoadModule(pol, "HandshakeContextRaw")
			if err != nil {
				return fmt.Errorf("loading handshake context module: %v", err)
			}
			cp[i].handshakeContext = modIface.(HandshakeContext)
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
				if pol.Drop {
					return nil, fmt.Errorf("dropping connection")
				}
				return pol.TLSConfig, nil
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
	matchers    []ConnectionMatcher

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

	// Reject TLS connections. EXPERIMENTAL: May change.
	Drop bool `json:"drop,omitempty"`

	// Enables and configures TLS client authentication.
	ClientAuthentication *ClientAuthentication `json:"client_authentication,omitempty"`

	// DefaultSNI becomes the ServerName in a ClientHello if there
	// is no policy configured for the empty SNI value.
	DefaultSNI string `json:"default_sni,omitempty"`

	// FallbackSNI becomes the ServerName in a ClientHello if
	// the original ServerName doesn't match any certificates
	// in the cache. The use cases for this are very niche;
	// typically if a client is a CDN and passes through the
	// ServerName of the downstream handshake but can accept
	// a certificate with the origin's hostname instead, then
	// you would set this to your origin's hostname. Note that
	// Caddy must be managing a certificate for this name.
	//
	// This feature is EXPERIMENTAL and subject to change or removal.
	FallbackSNI string `json:"fallback_sni,omitempty"`

	// Also known as "SSLKEYLOGFILE", TLS secrets will be written to
	// this file in NSS key log format which can then be parsed by
	// Wireshark and other tools. This is INSECURE as it allows other
	// programs or tools to decrypt TLS connections. However, this
	// capability can be useful for debugging and troubleshooting.
	// **ENABLING THIS LOG COMPROMISES SECURITY!**
	//
	// This feature is EXPERIMENTAL and subject to change or removal.
	InsecureSecretsLog string `json:"insecure_secrets_log,omitempty"`

	// A module that can manipulate the context passed into CertMagic's
	// certificate management functions during TLS handshakes.
	// EXPERIMENTAL - subject to change or removal.
	HandshakeContextRaw json.RawMessage `json:"handshake_context,omitempty" caddy:"namespace=tls.context inline_key=module"`
	handshakeContext    HandshakeContext

	// TLSConfig is the fully-formed, standard lib TLS config
	// used to serve TLS connections. Provision all
	// ConnectionPolicies to populate this. It is exported only
	// so it can be minimally adjusted after provisioning
	// if necessary (like to adjust NextProtos to disable HTTP/2),
	// and may be unexported in the future.
	TLSConfig *tls.Config `json:"-"`
}

type HandshakeContext interface {
	// HandshakeContext returns a context to pass into CertMagic's
	// GetCertificate function used to serve, load, and manage certs
	// during TLS handshakes. Generally you'll start with the context
	// from the ClientHelloInfo, but you may use other information
	// from it as well. Return an error to abort the handshake.
	HandshakeContext(*tls.ClientHelloInfo) (context.Context, error)
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
		NextProtos: p.ALPN,
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
			cfg.FallbackServerName = p.FallbackSNI

			// TODO: experimental: if a handshake context module is configured, allow it
			// to modify the context before passing it into CertMagic's GetCertificate
			ctx := hello.Context()
			if p.handshakeContext != nil {
				ctx, err = p.handshakeContext.HandshakeContext(hello)
				if err != nil {
					return nil, fmt.Errorf("handshake context: %v", err)
				}
			}

			return cfg.GetCertificateWithContext(ctx, hello)
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
	if !alpnFound && (cfg.NextProtos == nil || len(cfg.NextProtos) > 0) {
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
		if err := p.ClientAuthentication.provision(ctx); err != nil {
			return fmt.Errorf("provisioning client CA: %v", err)
		}
		if err := p.ClientAuthentication.ConfigureTLSConfig(cfg); err != nil {
			return fmt.Errorf("configuring TLS client authentication: %v", err)
		}

		// Prevent privilege escalation in case multiple vhosts are configured for
		// this TLS server; we could potentially figure out if that's the case, but
		// that might be complex to get right every time. Actually, two proper
		// solutions could leave tickets enabled, but I am not sure how to do them
		// properly without significant time investment; there may be new Go
		// APIs that alloaw this (Wrap/UnwrapSession?) but I do not know how to use
		// them at this time. TODO: one of these is a possible future enhancement:
		// A) Prevent resumptions across server identities (certificates): binding the ticket to the
		// certificate we would serve in a full handshake, or even bind a ticket to the exact SNI
		// it was issued under (though there are proposals for session resumption across hostnames).
		// B) Prevent resumptions falsely authenticating a client: include the realm in the ticket,
		// so that it can be validated upon resumption.
		cfg.SessionTicketsDisabled = true
	}

	if p.InsecureSecretsLog != "" {
		filename, err := caddy.NewReplacer().ReplaceOrErr(p.InsecureSecretsLog, true, true)
		if err != nil {
			return err
		}
		filename, err = caddy.FastAbs(filename)
		if err != nil {
			return err
		}
		logFile, _, err := secretsLogPool.LoadOrNew(filename, func() (caddy.Destructor, error) {
			w, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			return destructableWriter{w}, err
		})
		if err != nil {
			return err
		}
		ctx.OnCancel(func() { _, _ = secretsLogPool.Delete(filename) })

		cfg.KeyLogWriter = logFile.(io.Writer)

		if c := tlsApp.logger.Check(zapcore.WarnLevel, "TLS SECURITY COMPROMISED: secrets logging is enabled!"); c != nil {
			c.Write(zap.String("log_filename", filename))
		}
	}

	setDefaultTLSParams(cfg)

	p.TLSConfig = cfg

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
		p.DefaultSNI == "" &&
		p.InsecureSecretsLog == ""
}

// UnmarshalCaddyfile sets up the ConnectionPolicy from Caddyfile tokens. Syntax:
//
//	connection_policy {
//		alpn                  <values...>
//		cert_selection {
//			...
//		}
//		ciphers               <cipher_suites...>
//		client_auth {
//			...
//		}
//		curves                <curves...>
//		default_sni           <server_name>
//		match {
//			...
//		}
//		protocols             <min> [<max>]
//		# EXPERIMENTAL:
//		drop
//		fallback_sni          <server_name>
//		insecure_secrets_log  <log_file>
//	}
func (cp *ConnectionPolicy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val()

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasCertSelection, hasClientAuth, hasDefaultSNI, hasDrop,
		hasFallbackSNI, hasInsecureSecretsLog, hasMatch, hasProtocols bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "alpn":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			cp.ALPN = append(cp.ALPN, d.RemainingArgs()...)
		case "cert_selection":
			if hasCertSelection {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			p := &CustomCertSelectionPolicy{}
			if err := p.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			cp.CertSelection, hasCertSelection = p, true
		case "client_auth":
			if hasClientAuth {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			ca := &ClientAuthentication{}
			if err := ca.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			cp.ClientAuthentication, hasClientAuth = ca, true
		case "ciphers":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			cp.CipherSuites = append(cp.CipherSuites, d.RemainingArgs()...)
		case "curves":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			cp.Curves = append(cp.Curves, d.RemainingArgs()...)
		case "default_sni":
			if hasDefaultSNI {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, cp.DefaultSNI, hasDefaultSNI = d.NextArg(), d.Val(), true
		case "drop": // EXPERIMENTAL
			if hasDrop {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			cp.Drop, hasDrop = true, true
		case "fallback_sni": // EXPERIMENTAL
			if hasFallbackSNI {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, cp.FallbackSNI, hasFallbackSNI = d.NextArg(), d.Val(), true
		case "insecure_secrets_log": // EXPERIMENTAL
			if hasInsecureSecretsLog {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, cp.InsecureSecretsLog, hasInsecureSecretsLog = d.NextArg(), d.Val(), true
		case "match":
			if hasMatch {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			matcherSet, err := ParseCaddyfileNestedMatcherSet(d)
			if err != nil {
				return err
			}
			cp.MatchersRaw, hasMatch = matcherSet, true
		case "protocols":
			if hasProtocols {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() == 0 || d.CountRemainingArgs() > 2 {
				return d.ArgErr()
			}
			_, cp.ProtocolMin, hasProtocols = d.NextArg(), d.Val(), true
			if d.NextArg() {
				cp.ProtocolMax = d.Val()
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

// ClientAuthentication configures TLS client auth.
type ClientAuthentication struct {
	// Certificate authority module which provides the certificate pool of trusted certificates
	CARaw json.RawMessage `json:"ca,omitempty" caddy:"namespace=tls.ca_pool.source inline_key=provider"`
	ca    CA

	// Deprecated: Use the `ca` field with the `tls.ca_pool.source.inline` module instead.
	// A list of base64 DER-encoded CA certificates
	// against which to validate client certificates.
	// Client certs which are not signed by any of
	// these CAs will be rejected.
	TrustedCACerts []string `json:"trusted_ca_certs,omitempty"`

	// Deprecated: Use the `ca` field with the `tls.ca_pool.source.file` module instead.
	// TrustedCACertPEMFiles is a list of PEM file names
	// from which to load certificates of trusted CAs.
	// Client certificates which are not signed by any of
	// these CA certificates will be rejected.
	TrustedCACertPEMFiles []string `json:"trusted_ca_certs_pem_files,omitempty"`

	// Deprecated: This field is deprecated and will be removed in
	// a future version. Please use the `validators` field instead
	// with the tls.client_auth.verifier.leaf module instead.
	//
	// A list of base64 DER-encoded client leaf certs
	// to accept. If this list is not empty, client certs
	// which are not in this list will be rejected.
	TrustedLeafCerts []string `json:"trusted_leaf_certs,omitempty"`

	// Client certificate verification modules. These can perform
	// custom client authentication checks, such as ensuring the
	// certificate is not revoked.
	VerifiersRaw []json.RawMessage `json:"verifiers,omitempty" caddy:"namespace=tls.client_auth.verifier inline_key=verifier"`

	verifiers []ClientCertificateVerifier

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

// UnmarshalCaddyfile parses the Caddyfile segment to set up the client authentication. Syntax:
//
//	client_auth {
//		mode                   [request|require|verify_if_given|require_and_verify]
//	 	trust_pool			   <module> {
//			...
//		}
//		verifier               <module>
//	}
//
// If `mode` is not provided, it defaults to `require_and_verify` if `trust_pool` is provided.
// Otherwise, it defaults to `require`.
func (ca *ClientAuthentication) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.NextArg() {
		// consume any tokens on the same line, if any.
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdir := d.Val()
		switch subdir {
		case "mode":
			if d.CountRemainingArgs() > 1 {
				return d.ArgErr()
			}
			if !d.Args(&ca.Mode) {
				return d.ArgErr()
			}
		case "trusted_ca_cert":
			caddy.Log().Warn("The 'trusted_ca_cert' field is deprecated. Use the 'trust_pool' field instead.")
			if len(ca.CARaw) != 0 {
				return d.Err("cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'")
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			ca.TrustedCACerts = append(ca.TrustedCACerts, d.Val())
		case "trusted_leaf_cert":
			if !d.NextArg() {
				return d.ArgErr()
			}
			ca.TrustedLeafCerts = append(ca.TrustedLeafCerts, d.Val())
		case "trusted_ca_cert_file":
			caddy.Log().Warn("The 'trusted_ca_cert_file' field is deprecated. Use the 'trust_pool' field instead.")
			if len(ca.CARaw) != 0 {
				return d.Err("cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'")
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			filename := d.Val()
			ders, err := convertPEMFilesToDER(filename)
			if err != nil {
				return d.WrapErr(err)
			}
			ca.TrustedCACerts = append(ca.TrustedCACerts, ders...)
		case "trusted_leaf_cert_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			filename := d.Val()
			ders, err := convertPEMFilesToDER(filename)
			if err != nil {
				return d.WrapErr(err)
			}
			ca.TrustedLeafCerts = append(ca.TrustedLeafCerts, ders...)
		case "trust_pool":
			if len(ca.TrustedCACerts) != 0 {
				return d.Err("cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'")
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			modName := d.Val()
			mod, err := caddyfile.UnmarshalModule(d, "tls.ca_pool.source."+modName)
			if err != nil {
				return d.WrapErr(err)
			}
			caMod, ok := mod.(CA)
			if !ok {
				return fmt.Errorf("trust_pool module '%s' is not a certificate pool provider", caMod)
			}
			ca.CARaw = caddyconfig.JSONModuleObject(caMod, "provider", modName, nil)
		case "verifier":
			if !d.NextArg() {
				return d.ArgErr()
			}

			vType := d.Val()
			modID := "tls.client_auth.verifier." + vType
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}

			_, ok := unm.(ClientCertificateVerifier)
			if !ok {
				return d.Errf("module '%s' is not a caddytls.ClientCertificateVerifier", modID)
			}
			ca.VerifiersRaw = append(ca.VerifiersRaw, caddyconfig.JSONModuleObject(unm, "verifier", vType, nil))
		default:
			return d.Errf("unknown subdirective for client_auth: %s", subdir)
		}
	}

	// only trust_ca_cert or trust_ca_cert_file was specified
	if len(ca.TrustedCACerts) > 0 {
		fileMod := &InlineCAPool{}
		fileMod.TrustedCACerts = append(fileMod.TrustedCACerts, ca.TrustedCACerts...)
		ca.CARaw = caddyconfig.JSONModuleObject(fileMod, "provider", "inline", nil)
		ca.TrustedCACertPEMFiles, ca.TrustedCACerts = nil, nil
	}
	return nil
}

func convertPEMFilesToDER(filename string) ([]string, error) {
	certDataPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var ders []string
	// while block is not nil, we have more certificates in the file
	for block, rest := pem.Decode(certDataPEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("no CERTIFICATE pem block found in %s", filename)
		}
		ders = append(
			ders,
			base64.StdEncoding.EncodeToString(block.Bytes),
		)
	}
	// if we decoded nothing, return an error
	if len(ders) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE pem block found in %s", filename)
	}
	return ders, nil
}

func (clientauth *ClientAuthentication) provision(ctx caddy.Context) error {
	if len(clientauth.CARaw) > 0 && (len(clientauth.TrustedCACerts) > 0 || len(clientauth.TrustedCACertPEMFiles) > 0) {
		return fmt.Errorf("conflicting config for client authentication trust CA")
	}

	// convert all named file paths to inline
	if len(clientauth.TrustedCACertPEMFiles) > 0 {
		for _, fpath := range clientauth.TrustedCACertPEMFiles {
			ders, err := convertPEMFilesToDER(fpath)
			if err != nil {
				return nil
			}
			clientauth.TrustedCACerts = append(clientauth.TrustedCACerts, ders...)
		}
	}

	// if we have TrustedCACerts explicitly set, create an 'inline' CA and return
	if len(clientauth.TrustedCACerts) > 0 {
		clientauth.ca = InlineCAPool{
			TrustedCACerts: clientauth.TrustedCACerts,
		}
		return nil
	}

	// if we don't have any CARaw set, there's not much work to do
	if clientauth.CARaw == nil {
		return nil
	}
	caRaw, err := ctx.LoadModule(clientauth, "CARaw")
	if err != nil {
		return err
	}
	ca, ok := caRaw.(CA)
	if !ok {
		return fmt.Errorf("'ca' module '%s' is not a certificate pool provider", ca)
	}
	clientauth.ca = ca

	return nil
}

// Active returns true if clientauth has an actionable configuration.
func (clientauth ClientAuthentication) Active() bool {
	return len(clientauth.TrustedCACerts) > 0 ||
		len(clientauth.TrustedCACertPEMFiles) > 0 ||
		len(clientauth.TrustedLeafCerts) > 0 || // TODO: DEPRECATED
		len(clientauth.VerifiersRaw) > 0 ||
		len(clientauth.Mode) > 0 ||
		clientauth.CARaw != nil || clientauth.ca != nil
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
			len(clientauth.TrustedLeafCerts) > 0 ||
			clientauth.CARaw != nil || clientauth.ca != nil {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.RequireAnyClientCert
		}
	}

	// enforce CA verification by adding CA certs to the ClientCAs pool
	if clientauth.ca != nil {
		cfg.ClientCAs = clientauth.ca.CertPool()
	}

	// TODO: DEPRECATED: Only here for backwards compatibility.
	// If leaf cert is specified, enforce by adding a client auth module
	if len(clientauth.TrustedLeafCerts) > 0 {
		caddy.Log().Named("tls.connection_policy").Warn("trusted_leaf_certs is deprecated; use leaf verifier module instead")
		var trustedLeafCerts []*x509.Certificate
		for _, clientCertString := range clientauth.TrustedLeafCerts {
			clientCert, err := decodeBase64DERCert(clientCertString)
			if err != nil {
				return fmt.Errorf("parsing certificate: %v", err)
			}
			trustedLeafCerts = append(trustedLeafCerts, clientCert)
		}
		clientauth.verifiers = append(clientauth.verifiers, LeafCertClientAuth{trustedLeafCerts: trustedLeafCerts})
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
	for _, verifier := range clientauth.verifiers {
		err := verifier.VerifyClientCertificate(rawCerts, verifiedChains)
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
		// crypto/tls docs:
		// "If EncryptedClientHelloKeys is set, MinVersion, if set, must be VersionTLS13."
		if cfg.EncryptedClientHelloKeys == nil {
			cfg.MinVersion = tls.VersionTLS12
		} else {
			cfg.MinVersion = tls.VersionTLS13
		}
	}
	if cfg.MaxVersion == 0 {
		cfg.MaxVersion = tls.VersionTLS13
	}
}

// LeafCertClientAuth verifies the client's leaf certificate.
type LeafCertClientAuth struct {
	LeafCertificateLoadersRaw []json.RawMessage `json:"leaf_certs_loaders,omitempty" caddy:"namespace=tls.leaf_cert_loader inline_key=loader"`
	trustedLeafCerts          []*x509.Certificate
}

// CaddyModule returns the Caddy module information.
func (LeafCertClientAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_auth.verifier.leaf",
		New: func() caddy.Module { return new(LeafCertClientAuth) },
	}
}

func (l *LeafCertClientAuth) Provision(ctx caddy.Context) error {
	if l.LeafCertificateLoadersRaw == nil {
		return nil
	}
	val, err := ctx.LoadModule(l, "LeafCertificateLoadersRaw")
	if err != nil {
		return fmt.Errorf("could not parse leaf certificates loaders: %s", err.Error())
	}
	trustedLeafCertloaders := []LeafCertificateLoader{}
	for _, loader := range val.([]any) {
		trustedLeafCertloaders = append(trustedLeafCertloaders, loader.(LeafCertificateLoader))
	}
	trustedLeafCertificates := []*x509.Certificate{}
	for _, loader := range trustedLeafCertloaders {
		certs, err := loader.LoadLeafCertificates()
		if err != nil {
			return fmt.Errorf("could not load leaf certificates: %s", err.Error())
		}
		trustedLeafCertificates = append(trustedLeafCertificates, certs...)
	}
	l.trustedLeafCerts = trustedLeafCertificates
	return nil
}

func (l LeafCertClientAuth) VerifyClientCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	remoteLeafCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("can't parse the given certificate: %s", err.Error())
	}

	for _, trustedLeafCert := range l.trustedLeafCerts {
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

// LeafCertificateLoader is a type that loads the trusted leaf certificates
// for the tls.leaf_cert_loader modules
type LeafCertificateLoader interface {
	LoadLeafCertificates() ([]*x509.Certificate, error)
}

// ClientCertificateVerifier is a type which verifies client certificates.
// It is called during verifyPeerCertificate in the TLS handshake.
type ClientCertificateVerifier interface {
	VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

var defaultALPN = []string{"h2", "http/1.1"}

type destructableWriter struct{ *os.File }

func (d destructableWriter) Destruct() error { return d.Close() }

var secretsLogPool = caddy.NewUsagePool()

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*ClientAuthentication)(nil)
	_ caddyfile.Unmarshaler = (*ConnectionPolicy)(nil)
)

// ParseCaddyfileNestedMatcherSet parses the Caddyfile tokens for a nested
// matcher set, and returns its raw module map value.
func ParseCaddyfileNestedMatcherSet(d *caddyfile.Dispenser) (caddy.ModuleMap, error) {
	matcherMap := make(map[string]ConnectionMatcher)

	tokensByMatcherName := make(map[string][]caddyfile.Token)
	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		matcherName := d.Val()
		tokensByMatcherName[matcherName] = append(tokensByMatcherName[matcherName], d.NextSegment()...)
	}

	for matcherName, tokens := range tokensByMatcherName {
		dd := caddyfile.NewDispenser(tokens)
		dd.Next() // consume wrapper name

		unm, err := caddyfile.UnmarshalModule(dd, "tls.handshake_match."+matcherName)
		if err != nil {
			return nil, err
		}
		cm, ok := unm.(ConnectionMatcher)
		if !ok {
			return nil, fmt.Errorf("matcher module '%s' is not a connection matcher", matcherName)
		}
		matcherMap[matcherName] = cm
	}

	matcherSet := make(caddy.ModuleMap)
	for name, matcher := range matcherMap {
		jsonBytes, err := json.Marshal(matcher)
		if err != nil {
			return nil, fmt.Errorf("marshaling %T matcher: %v", matcher, err)
		}
		matcherSet[name] = jsonBytes
	}

	return matcherSet, nil
}
