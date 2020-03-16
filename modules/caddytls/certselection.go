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
	"fmt"
	"math/big"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

func init() {
	caddy.RegisterModule(CustomCertSelectionPolicy{})
}

// CustomCertSelectionPolicy represents a policy for selecting the certificate
// used to complete a handshake when there may be multiple options. All fields
// specified must match the candidate certificate for it to be chosen.
// This was needed to solve https://github.com/caddyserver/caddy/issues/2588.
type CustomCertSelectionPolicy struct {
	SerialNumber        *big.Int           `json:"serial_number,omitempty"`
	SubjectOrganization string             `json:"subject_organization,omitempty"`
	PublicKeyAlgorithm  PublicKeyAlgorithm `json:"public_key_algorithm,omitempty"`
	Tag                 string             `json:"tag,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (CustomCertSelectionPolicy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificate_selection.custom",
		New: func() caddy.Module { return new(CustomCertSelectionPolicy) },
	}
}

// SelectCertificate implements certmagic.CertificateSelector.
func (p CustomCertSelectionPolicy) SelectCertificate(_ *tls.ClientHelloInfo, choices []certmagic.Certificate) (certmagic.Certificate, error) {
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
var _ certmagic.CertificateSelector = (*CustomCertSelectionPolicy)(nil)
