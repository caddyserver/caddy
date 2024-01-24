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
	"crypto/x509"
	"fmt"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(LeafDERLoader{})
}

// LeafDERLoader loads leaf certificates by
// decoding their DER blocks directly. This has the advantage
// of not needing to store them on disk at all.
type LeafDERLoader struct {
	Ders []LeafCertDER `json:"ders,omitempty"`
}

// Provision implements caddy.Provisioner.
func (pl LeafDERLoader) Provision(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for k, pair := range pl.Ders {
		for i, tag := range pair.Tags {
			pair.Tags[i] = repl.ReplaceKnown(tag, "")
		}
		pl.Ders[k] = LeafCertDER{
			CertificateDER: repl.ReplaceKnown(pair.CertificateDER, ""),
			Tags:           pair.Tags,
		}
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (LeafDERLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.leaf_cert_loader.der",
		New: func() caddy.Module { return new(LeafDERLoader) },
	}
}

// LeafCertDER contains DER-encoded Leaf certificate.
type LeafCertDER struct {
	// The leaf certificate in DER format.
	CertificateDER string `json:"certificate"`

	// Arbitrary values to associate with this certificate.
	// Can be useful when you want to select a particular
	// certificate when there may be multiple valid candidates.
	Tags []string `json:"tags,omitempty"`
}

// LoadLeafCertificates returns the certificates contained in pl.
func (pl LeafDERLoader) LoadLeafCertificates() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(pl.Ders))
	for i, pair := range pl.Ders {
		cert, err := x509.ParseCertificate([]byte(pair.CertificateDER))
		if err != nil {
			return nil, fmt.Errorf("DER cert %d: %v", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// Interface guard
var (
	_ LeafCertificateLoader = (*LeafDERLoader)(nil)
	_ caddy.Provisioner     = (*LeafDERLoader)(nil)
)
