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
	Files []string `json:"files,omitempty"`
}

// Provision implements caddy.Provisioner.
func (fl *LeafFileLoader) Provision(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for k, path := range fl.Files {
		fl.Files[k] = repl.ReplaceKnown(path, "")
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

// LoadLeafCertificates returns the certificates to be loaded by fl.
func (fl LeafFileLoader) LoadLeafCertificates() ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, 0, len(fl.Files))
	for _, path := range fl.Files {
		ders, err := convertPEMFilesToDERBytes(path)
		if err != nil {
			return nil, err
		}
		certs, err := x509.ParseCertificates(ders)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certs...)
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
