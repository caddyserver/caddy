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
	"encoding/pem"
	"fmt"
	"os"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(LeafFileLoader{})
}

// LeafFileLoader loads leaf certificates from disk.
type LeafFileLoader struct {
	Files []LeafCertFile `json:"files,omitempty"`
}

// Provision implements caddy.Provisioner.
func (fl LeafFileLoader) Provision(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for k, pair := range fl.Files {
		for i, tag := range pair.Tags {
			pair.Tags[i] = repl.ReplaceKnown(tag, "")
		}
		fl.Files[k] = LeafCertFile{
			LeafCertificate: repl.ReplaceKnown(pair.LeafCertificate, ""),
			Format:          repl.ReplaceKnown(pair.Format, ""),
			Tags:            pair.Tags,
		}
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (LeafFileLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.leaf_cert_loader.file",
		New: func() caddy.Module { return new(LeafFileLoader) },
	}
}

// LeafCertFile associates leaf certificate file name along with its
// encoding format so that they can be loaded from disk.
type LeafCertFile struct {
	// Path to the certificate file.
	LeafCertificate string `json:"certificate"`

	// The format of the cert. Can be "pem". Default: "pem"
	Format string `json:"format,omitempty"`

	// Arbitrary values to associate with this certificate.
	// Can be useful when you want to select a particular
	// certificate when there may be multiple valid candidates.
	Tags []string `json:"tags,omitempty"`
}

// LoadLEafCertificates returns the certificates to be loaded by fl.
func (fl LeafFileLoader) LoadLeafCertificates() ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, 0, len(fl.Files))
	for _, pair := range fl.Files {
		switch pair.Format {
		case "":
			fallthrough
		case "pem":
			ders, err := convertPEMFilesToDERBytes(pair.LeafCertificate)
			if err != nil {
				return nil, err
			}
			certs, err := x509.ParseCertificates(ders)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, certs...)
		default:
			return nil, fmt.Errorf("unrecognized certificate/key encoding format: %s", pair.Format)
		}
	}
	return certificates, nil
}

func convertPEMFilesToDERBytes(filename string) ([]byte, error) {
	certDataPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var ders []byte
	// while block is not nil, we have more certificates in the file
	for block, rest := pem.Decode(certDataPEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("no CERTIFICATE pem block found in %s", filename)
		}
		ders = append(
			ders,
			block.Bytes...,
		)
	}
	// if we decoded nothing, return an error
	if len(ders) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE pem block found in %s", filename)
	}
	return ders, nil
}

// Interface guard
var (
	_ LeafCertificateLoader = (*LeafFileLoader)(nil)
	_ caddy.Provisioner     = (*LeafFileLoader)(nil)
)
