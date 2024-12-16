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
	"slices"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
			found := slices.ContainsFunc(p.SubjectOrganization, func(s string) bool {
				return slices.Contains(cert.Leaf.Subject.Organization, s)
			})
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

// UnmarshalCaddyfile sets up the CustomCertSelectionPolicy from Caddyfile tokens. Syntax:
//
//	cert_selection {
//		all_tags             <values...>
//		any_tag              <values...>
//		public_key_algorithm <dsa|ecdsa|rsa>
//		serial_number        <big_integers...>
//		subject_organization <values...>
//	}
func (p *CustomCertSelectionPolicy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasPublicKeyAlgorithm bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "all_tags":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			p.AllTags = append(p.AllTags, d.RemainingArgs()...)
		case "any_tag":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			p.AnyTag = append(p.AnyTag, d.RemainingArgs()...)
		case "public_key_algorithm":
			if hasPublicKeyAlgorithm {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			if err := p.PublicKeyAlgorithm.UnmarshalJSON([]byte(d.Val())); err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
			}
			hasPublicKeyAlgorithm = true
		case "serial_number":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				val, bi := d.Val(), bigInt{}
				_, ok := bi.SetString(val, 10)
				if !ok {
					return d.Errf("parsing %s option '%s': invalid big.int value %s", wrapper, optionName, val)
				}
				p.SerialNumber = append(p.SerialNumber, bi)
			}
		case "subject_organization":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			p.SubjectOrganization = append(p.SubjectOrganization, d.RemainingArgs()...)
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

// Interface guard
var _ caddyfile.Unmarshaler = (*CustomCertSelectionPolicy)(nil)
