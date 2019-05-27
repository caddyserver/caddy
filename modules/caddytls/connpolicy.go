package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"bitbucket.org/lightcodelabs/caddy2"
	"github.com/go-acme/lego/challenge/tlsalpn01"
	"github.com/mholt/certmagic"
)

// ConnectionPolicies is an ordered group of connection policies;
// the first matching policy will be used to configure TLS
// connections at handshake-time.
type ConnectionPolicies []*ConnectionPolicy

// TLSConfig converts the group of policies to a standard-lib-compatible
// TLS configuration which selects the first matching policy based on
// the ClientHello.
func (cp ConnectionPolicies) TLSConfig(ctx caddy2.Context) (*tls.Config, error) {
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
		cp[i].Matchers = nil // allow GC to deallocate - TODO: Does this help?

		// certificate selector
		if pol.CertSelection != nil {
			val, err := ctx.LoadModuleInline("policy", "tls.certificate_selection", pol.CertSelection)
			if err != nil {
				return nil, fmt.Errorf("loading certificate selection module: %s", err)
			}
			cp[i].certSelector = val.(certmagic.CertificateSelector)
			cp[i].CertSelection = nil // allow GC to deallocate - TODO: Does this help?
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

	CipherSuites []string `json:"cipher_suites,omitempty"`
	Curves       []string `json:"curves,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
	ProtocolMin  string   `json:"protocol_min,omitempty"`
	ProtocolMax  string   `json:"protocol_max,omitempty"`

	// TODO: Client auth

	// TODO: see if starlark could be useful here - enterprise only
	StarlarkHandshake string `json:"starlark_handshake,omitempty"`

	matchers     []ConnectionMatcher
	certSelector certmagic.CertificateSelector

	stdTLSConfig *tls.Config
}

func (p *ConnectionPolicy) buildStandardTLSConfig(ctx caddy2.Context) error {
	tlsAppIface, err := ctx.App("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}
	tlsApp := tlsAppIface.(*TLS)

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
		// TODO: Session ticket key rotation (use Storage)
	}

	// add all the cipher suites in order, without duplicates
	cipherSuitesAdded := make(map[uint16]struct{})
	for _, csName := range p.CipherSuites {
		csID := supportedCipherSuites[csName]
		if _, ok := cipherSuitesAdded[csID]; !ok {
			cipherSuitesAdded[csID] = struct{}{}
			cfg.CipherSuites = append(cfg.CipherSuites, csID)
		}
	}

	// add all the curve preferences in order, without duplicates
	curvesAdded := make(map[tls.CurveID]struct{})
	for _, curveName := range p.Curves {
		curveID := supportedCurves[curveName]
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
		cfg.MinVersion = supportedProtocols[p.ProtocolMin]
	}
	if p.ProtocolMax != "" {
		cfg.MaxVersion = supportedProtocols[p.ProtocolMax]
	}
	if p.ProtocolMin > p.ProtocolMax {
		return fmt.Errorf("protocol min (%x) cannot be greater than protocol max (%x)", p.ProtocolMin, p.ProtocolMax)
	}

	// TODO: client auth, and other fields

	p.stdTLSConfig = cfg

	return nil
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
