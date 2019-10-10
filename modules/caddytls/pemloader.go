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
	"fmt"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(PEMLoader{})
}

// PEMLoader loads certificates and their associated keys by
// decoding their PEM blocks directly. This has the advantage
// of not needing to store them on disk at all.
type PEMLoader []CertKeyPEMPair

// CaddyModule returns the Caddy module information.
func (PEMLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "tls.certificates.load_pem",
		New:  func() caddy.Module { return PEMLoader{} },
	}
}

// CertKeyPEMPair pairs certificate and key PEM blocks.
type CertKeyPEMPair struct {
	CertificatePEM string   `json:"certificate"`
	KeyPEM         string   `json:"key"`
	Tags           []string `json:"tags,omitempty"`
}

// LoadCertificates returns the certificates contained in pl.
func (pl PEMLoader) LoadCertificates() ([]Certificate, error) {
	var certs []Certificate
	for i, pair := range pl {
		cert, err := tls.X509KeyPair([]byte(pair.CertificatePEM), []byte(pair.KeyPEM))
		if err != nil {
			return nil, fmt.Errorf("PEM pair %d: %v", i, err)
		}
		certs = append(certs, Certificate{
			Certificate: cert,
			Tags:        pair.Tags,
		})
	}
	return certs, nil
}

// Interface guard
var _ CertificateLoader = (PEMLoader)(nil)
