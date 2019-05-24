package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
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
	// connection policy matchers
	for i, pol := range cp {
		for modName, rawMsg := range pol.MatchersRaw {
			val, err := ctx.LoadModule("tls.handshake_match."+modName, rawMsg)
			if err != nil {
				return nil, fmt.Errorf("loading handshake matcher module '%s': %s", modName, err)
			}
			cp[i].matchers = append(cp[i].matchers, val.(ConnectionMatcher))
		}
		cp[i].MatchersRaw = nil // allow GC to deallocate - TODO: Does this help?
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
	MatchersRaw map[string]json.RawMessage `json:"match,omitempty"`

	CipherSuites []string `json:"cipher_suites,omitempty"`
	Curves       []string `json:"curves,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
	ProtocolMin  string   `json:"protocol_min,omitempty"`
	ProtocolMax  string   `json:"protocol_max,omitempty"`

	CertSelection *CertSelectionPolicy `json:"certificate_selection,omitempty"`

	// TODO: Client auth

	// TODO: see if starlark could be useful here - enterprise only
	StarlarkHandshake string `json:"starlark_handshake,omitempty"`

	matchers     []ConnectionMatcher
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
			if p.CertSelection != nil {
				newCfg.CertSelector = makeCertSelector(p)
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

// CertSelectionPolicy represents a policy for selecting the certificate
// used to complete a handshake when there may be multiple options. All
// fields specified must match the candidate certificate for it to be chosen.
// This was needed to solve https://github.com/mholt/caddy/issues/2588.
type CertSelectionPolicy struct {
	SerialNumber        *big.Int    `json:"serial_number,omitempty"`
	SubjectOrganization string      `json:"subject.organization,omitempty"`
	PublicKeyAlgorithm  pkAlgorithm `json:"public_key_algorithm,omitempty"`
}

func makeCertSelector(p *ConnectionPolicy) func(*tls.ClientHelloInfo, []certmagic.Certificate) (certmagic.Certificate, error) {
	return func(hello *tls.ClientHelloInfo, choices []certmagic.Certificate) (certmagic.Certificate, error) {
		for _, cert := range choices {
			var matchOrg bool
			if p.CertSelection.SubjectOrganization != "" {
				for _, org := range cert.Subject.Organization {
					if p.CertSelection.SubjectOrganization == org {
						matchOrg = true
						break
					}
				}
			}
			if !matchOrg {
				continue
			}
			if p.CertSelection.PublicKeyAlgorithm != pkAlgorithm(x509.UnknownPublicKeyAlgorithm) &&
				pkAlgorithm(cert.PublicKeyAlgorithm) != p.CertSelection.PublicKeyAlgorithm {
				continue
			}
			if p.CertSelection.SerialNumber != nil &&
				cert.SerialNumber.Cmp(p.CertSelection.SerialNumber) != 0 {
				continue
			}
			return cert, nil
		}
		return certmagic.Certificate{}, fmt.Errorf("no certificates matched custom selection policy")
	}
}

type pkAlgorithm x509.PublicKeyAlgorithm

// UnmarshalJSON satisfies json.Unmarshaler.
func (a *pkAlgorithm) UnmarshalJSON(b []byte) error {
	algoStr := strings.ToLower(strings.Trim(string(b), `"`))
	algo, ok := publicKeyAlgorithms[algoStr]
	if !ok {
		return fmt.Errorf("unrecognized public key algorithm: %s (expected one of %v)",
			algoStr, publicKeyAlgorithms)
	}
	a = &algo
	return nil
}

// ConnectionMatcher is a type which matches TLS handshakes.
type ConnectionMatcher interface {
	Match(*tls.ClientHelloInfo) bool
}
