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
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(LeafStorageLoader{})
}

// LeafStorageLoader loads leaf certificates from the
// globally configured storage module.
type LeafStorageLoader struct {
	// A list of certificate file names to be loaded from storage.
	Certificates []string `json:"certificates,omitempty"`

	// The storage module where the trusted leaf certificates are stored. Absent
	// explicit storage implies the use of Caddy default storage.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	// Reference to the globally configured storage module.
	storage certmagic.Storage

	ctx caddy.Context
}

// CaddyModule returns the Caddy module information.
func (LeafStorageLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.leaf_cert_loader.storage",
		New: func() caddy.Module { return new(LeafStorageLoader) },
	}
}

// Provision loads the storage module for sl.
func (sl *LeafStorageLoader) Provision(ctx caddy.Context) error {
	if sl.StorageRaw != nil {
		val, err := ctx.LoadModule(sl, "StorageRaw")
		if err != nil {
			return fmt.Errorf("loading storage module: %v", err)
		}
		cmStorage, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating storage configuration: %v", err)
		}
		sl.storage = cmStorage
	}
	if sl.storage == nil {
		sl.storage = ctx.Storage()
	}
	sl.ctx = ctx

	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for k, path := range sl.Certificates {
		sl.Certificates[k] = repl.ReplaceKnown(path, "")
	}
	return nil
}

// LoadLeafCertificates returns the certificates to be loaded by sl.
func (sl LeafStorageLoader) LoadLeafCertificates() ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, 0, len(sl.Certificates))
	for _, path := range sl.Certificates {
		certData, err := sl.storage.Load(sl.ctx, path)
		if err != nil {
			return nil, err
		}

		ders, err := convertPEMToDER(certData)
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

func convertPEMToDER(pemData []byte) ([]byte, error) {
	var ders []byte
	// while block is not nil, we have more certificates in the file
	for block, rest := pem.Decode(pemData); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("no CERTIFICATE pem block found in the given pem data")
		}
		ders = append(
			ders,
			block.Bytes...,
		)
	}
	// if we decoded nothing, return an error
	if len(ders) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE pem block found in the given pem data")
	}
	return ders, nil
}

// Interface guard
var (
	_ LeafCertificateLoader = (*LeafStorageLoader)(nil)
	_ caddy.Provisioner     = (*LeafStorageLoader)(nil)
)
