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
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(FileLoader{})
}

// FileLoader loads certificates and their associated keys from disk.
type FileLoader []CertKeyFilePair

// Provision implements caddy.Provisioner.
func (fl FileLoader) Provision(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for k, pair := range fl {
		for i, tag := range pair.Tags {
			pair.Tags[i] = repl.ReplaceKnown(tag, "")
		}
		fl[k] = CertKeyFilePair{
			Certificate: repl.ReplaceKnown(pair.Certificate, ""),
			Key:         repl.ReplaceKnown(pair.Key, ""),
			Format:      repl.ReplaceKnown(pair.Format, ""),
			Tags:        pair.Tags,
		}
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (FileLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.load_files",
		New: func() caddy.Module { return new(FileLoader) },
	}
}

// CertKeyFilePair pairs certificate and key file names along with their
// encoding format so that they can be loaded from disk.
type CertKeyFilePair struct {
	// Path to the certificate (public key) file.
	Certificate string `json:"certificate"`

	// Path to the private key file.
	Key string `json:"key"`

	// The format of the cert and key. Can be "pem". Default: "pem"
	Format string `json:"format,omitempty"`

	// Arbitrary values to associate with this certificate.
	// Can be useful when you want to select a particular
	// certificate when there may be multiple valid candidates.
	Tags []string `json:"tags,omitempty"`
}

// LoadCertificates returns the certificates to be loaded by fl.
func (fl FileLoader) LoadCertificates() ([]Certificate, error) {
	certs := make([]Certificate, 0, len(fl))
	for _, pair := range fl {
		certData, err := os.ReadFile(pair.Certificate)
		if err != nil {
			return nil, err
		}
		keyData, err := os.ReadFile(pair.Key)
		if err != nil {
			return nil, err
		}

		var cert tls.Certificate
		switch pair.Format {
		case "":
			fallthrough

		case "pem":
			// if the start of the key file looks like an encrypted private key,
			// reject it with a helpful error message
			if strings.Contains(string(keyData[:40]), "ENCRYPTED") {
				return nil, fmt.Errorf("encrypted private keys are not supported; please decrypt the key first")
			}

			cert, err = tls.X509KeyPair(certData, keyData)

		default:
			return nil, fmt.Errorf("unrecognized certificate/key encoding format: %s", pair.Format)
		}
		if err != nil {
			return nil, err
		}

		certs = append(certs, Certificate{Certificate: cert, Tags: pair.Tags})
	}
	return certs, nil
}

// Interface guard
var (
	_ CertificateLoader = (FileLoader)(nil)
	_ caddy.Provisioner = (FileLoader)(nil)
)
