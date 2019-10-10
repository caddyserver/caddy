package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/certmagic"
)

func init() {
	caddy.RegisterModule(Policy{})
}

// Policy represents a policy for selecting the certificate used to
// complete a handshake when there may be multiple options. All fields
// specified must match the candidate certificate for it to be chosen.
// This was needed to solve https://github.com/caddyserver/caddy/issues/2588.
type Policy struct {
	SerialNumber        *big.Int           `json:"serial_number,omitempty"`
	SubjectOrganization string             `json:"subject_organization,omitempty"`
	PublicKeyAlgorithm  PublicKeyAlgorithm `json:"public_key_algorithm,omitempty"`
	Tag                 string             `json:"tag,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Policy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "tls.certificate_selection.custom",
		New:  func() caddy.Module { return new(Policy) },
	}
}

// SelectCertificate implements certmagic.CertificateSelector.
func (p Policy) SelectCertificate(_ *tls.ClientHelloInfo, choices []certmagic.Certificate) (certmagic.Certificate, error) {
	for _, cert := range choices {
		if p.SerialNumber != nil && cert.SerialNumber.Cmp(p.SerialNumber) != 0 {
			continue
		}

		if p.PublicKeyAlgorithm != PublicKeyAlgorithm(x509.UnknownPublicKeyAlgorithm) &&
			PublicKeyAlgorithm(cert.PublicKeyAlgorithm) != p.PublicKeyAlgorithm {
			continue
		}

		if p.SubjectOrganization != "" {
			var matchOrg bool
			for _, org := range cert.Subject.Organization {
				if p.SubjectOrganization == org {
					matchOrg = true
					break
				}
			}
			if !matchOrg {
				continue
			}
		}

		if p.Tag != "" && !cert.HasTag(p.Tag) {
			continue
		}

		return cert, nil
	}
	return certmagic.Certificate{}, fmt.Errorf("no certificates matched custom selection policy")
}

// Interface guard
var _ certmagic.CertificateSelector = (*Policy)(nil)
