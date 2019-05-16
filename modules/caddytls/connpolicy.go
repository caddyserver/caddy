package caddytls

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

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
			cp[i].Matchers = append(cp[i].Matchers, val.(ConnectionMatcher))
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

	return &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		policyLoop:
			for _, pol := range cp {
				for _, matcher := range pol.Matchers {
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

	// TODO: Client auth

	// TODO: see if starlark could be useful here - enterprise only
	StarlarkHandshake string `json:"starlark_handshake,omitempty"`

	Matchers     []ConnectionMatcher
	stdTLSConfig *tls.Config
}

func (cp *ConnectionPolicy) buildStandardTLSConfig(ctx caddy2.Context) error {
	tlsAppIface, err := ctx.App("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}
	tlsApp := tlsAppIface.(*TLS)

	cfg := &tls.Config{
		NextProtos:               cp.ALPN,
		PreferServerCipherSuites: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// TODO: Must fix https://github.com/mholt/caddy/issues/2588
			// (allow customizing the selection of a very specific certificate
			// based on the ClientHelloInfo)
			cfgTpl, err := tlsApp.getConfigForName(hello.ServerName)
			if err != nil {
				return nil, fmt.Errorf("getting config for name %s: %v", hello.ServerName, err)
			}
			newCfg := certmagic.New(tlsApp.certCache, cfgTpl)
			return newCfg.GetCertificate(hello)
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		// TODO: Session ticket key rotation (use Storage)
	}

	// add all the cipher suites in order, without duplicates
	cipherSuitesAdded := make(map[uint16]struct{})
	for _, csName := range cp.CipherSuites {
		csID := supportedCipherSuites[csName]
		if _, ok := cipherSuitesAdded[csID]; !ok {
			cipherSuitesAdded[csID] = struct{}{}
			cfg.CipherSuites = append(cfg.CipherSuites, csID)
		}
	}

	// add all the curve preferences in order, without duplicates
	curvesAdded := make(map[tls.CurveID]struct{})
	for _, curveName := range cp.Curves {
		curveID := supportedCurves[curveName]
		if _, ok := curvesAdded[curveID]; !ok {
			curvesAdded[curveID] = struct{}{}
			cfg.CurvePreferences = append(cfg.CurvePreferences, curveID)
		}
	}

	// ensure ALPN includes the ACME TLS-ALPN protocol
	var alpnFound bool
	for _, a := range cp.ALPN {
		if a == tlsalpn01.ACMETLS1Protocol {
			alpnFound = true
			break
		}
	}
	if !alpnFound {
		cfg.NextProtos = append(cfg.NextProtos, tlsalpn01.ACMETLS1Protocol)
	}

	// min and max protocol versions
	if cp.ProtocolMin != "" {
		cfg.MinVersion = supportedProtocols[cp.ProtocolMin]
	}
	if cp.ProtocolMax != "" {
		cfg.MaxVersion = supportedProtocols[cp.ProtocolMax]
	}
	if cp.ProtocolMin > cp.ProtocolMax {
		return fmt.Errorf("protocol min (%x) cannot be greater than protocol max (%x)", cp.ProtocolMin, cp.ProtocolMax)
	}

	// TODO: client auth, and other fields

	cp.stdTLSConfig = cfg

	return nil
}

// ConnectionMatcher is a type which matches TLS handshakes.
type ConnectionMatcher interface {
	Match(*tls.ClientHelloInfo) bool
}
