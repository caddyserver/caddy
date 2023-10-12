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
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/caddyserver/certmagic"
)

// CustomCertSelectionPolicy represents a policy for selecting the certificate
// used to complete a handshake when there may be multiple options. All fields
// specified must match the candidate certificate for it to be chosen.
// This was needed to solve https://github.com/caddyserver/caddy/issues/2588.
type CustomCertSelectionPolicy struct {
	// The certificate must have one of these serial numbers.
	SerialNumber []bigInt `json:"serial_number,omitempty"`

	// The certificate must have one of these organization names.
	SubjectOrganization []string `json:"subject_organization,omitempty"`

	// The certificate must use this public key algorithm.
	PublicKeyAlgorithm PublicKeyAlgorithm `json:"public_key_algorithm,omitempty"`

	// The certificate must have at least one of the tags in the list.
	AnyTag []string `json:"any_tag,omitempty"`

	// The certificate must have all of the tags in the list.
	AllTags []string `json:"all_tags,omitempty"`
}

// SelectCertificate implements certmagic.CertificateSelector. It
// only chooses a certificate that at least meets the criteria in
// p. It then chooses the first non-expired certificate that is
// compatible with the client. If none are valid, it chooses the
// first viable candidate anyway.
func (p CustomCertSelectionPolicy) SelectCertificate(hello *tls.ClientHelloInfo, choices []certmagic.Certificate) (certmagic.Certificate, error) {
	viable := make([]certmagic.Certificate, 0, len(choices))

nextChoice:
	for _, cert := range choices {
		if len(p.SerialNumber) > 0 {
			var found bool
			for _, sn := range p.SerialNumber {
				snInt := sn.Int // avoid taking address of iteration variable (gosec warning)
				if cert.Leaf.SerialNumber.Cmp(&snInt) == 0 {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if len(p.SubjectOrganization) > 0 {
			var found bool
			for _, subjOrg := range p.SubjectOrganization {
				for _, org := range cert.Leaf.Subject.Organization {
					if subjOrg == org {
						found = true
						break
					}
				}
			}
			if !found {
				continue
			}
		}

		if p.PublicKeyAlgorithm != PublicKeyAlgorithm(x509.UnknownPublicKeyAlgorithm) &&
			PublicKeyAlgorithm(cert.Leaf.PublicKeyAlgorithm) != p.PublicKeyAlgorithm {
			continue
		}

		if len(p.AnyTag) > 0 {
			var found bool
			for _, tag := range p.AnyTag {
				if cert.HasTag(tag) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if len(p.AllTags) > 0 {
			for _, tag := range p.AllTags {
				if !cert.HasTag(tag) {
					continue nextChoice
				}
			}
		}

		// this certificate at least meets the policy's requirements,
		// but we still have to check expiration and compatibility
		viable = append(viable, cert)
	}

	if len(viable) == 0 {
		return certmagic.Certificate{}, fmt.Errorf("no certificates matched custom selection policy")
	}

	return certmagic.DefaultCertificateSelector(hello, viable)
}

// bigInt is a big.Int type that interops with JSON encodings as a string.
type bigInt struct{ big.Int }

func (bi bigInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(bi.String())
}

func (bi *bigInt) UnmarshalJSON(p []byte) error {
	if string(p) == "null" {
		return nil
	}
	var stringRep string
	err := json.Unmarshal(p, &stringRep)
	if err != nil {
		return err
	}
	_, ok := bi.SetString(stringRep, 10)
	if !ok {
		return fmt.Errorf("not a valid big integer: %s", p)
	}
	return nil
}
