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
	"github.com/caddyserver/certmagic"
)

func init() {
	caddy.RegisterModule(StorageLoader{})
}

// StorageLoader loads certificates and their associated keys
// from the globally configured storage module.
type StorageLoader struct {
	// A list of pairs of certificate and key file names along with their
	// encoding format so that they can be loaded from storage.
	Pairs []CertKeyFilePair `json:"pairs,omitempty"`

	// Reference to the globally configured storage module.
	storage certmagic.Storage
}

// CaddyModule returns the Caddy module information.
func (StorageLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.load_storage",
		New: func() caddy.Module { return new(StorageLoader) },
	}
}

// Provision loads the storage module for sl.
func (sl *StorageLoader) Provision(ctx caddy.Context) error {
	sl.storage = ctx.Storage()
	return nil
}

// LoadCertificates returns the certificates to be loaded by sl.
func (sl StorageLoader) LoadCertificates() ([]Certificate, error) {
	certs := make([]Certificate, 0, len(sl.Pairs))
	for _, pair := range sl.Pairs {
		certData, err := sl.storage.Load(pair.Certificate)
		if err != nil {
			return nil, err
		}
		keyData, err := sl.storage.Load(pair.Key)
		if err != nil {
			return nil, err
		}

		var cert tls.Certificate
		switch pair.Format {
		case "":
			fallthrough
		case "pem":
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
	_ CertificateLoader = (*StorageLoader)(nil)
	_ caddy.Provisioner = (*StorageLoader)(nil)
)
