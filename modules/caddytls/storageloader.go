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
	"strings"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
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

	ctx caddy.Context
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
	sl.ctx = ctx

	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for k, pair := range sl.Pairs {
		for i, tag := range pair.Tags {
			pair.Tags[i] = repl.ReplaceKnown(tag, "")
		}
		sl.Pairs[k] = CertKeyFilePair{
			Certificate: repl.ReplaceKnown(pair.Certificate, ""),
			Key:         repl.ReplaceKnown(pair.Key, ""),
			Format:      repl.ReplaceKnown(pair.Format, ""),
			Tags:        pair.Tags,
		}
	}
	return nil
}

// LoadCertificates returns the certificates to be loaded by sl.
func (sl StorageLoader) LoadCertificates() ([]Certificate, error) {
	certs := make([]Certificate, 0, len(sl.Pairs))
	for _, pair := range sl.Pairs {
		certData, err := sl.storage.Load(sl.ctx, pair.Certificate)
		if err != nil {
			return nil, err
		}
		keyData, err := sl.storage.Load(sl.ctx, pair.Key)
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
	_ CertificateLoader = (*StorageLoader)(nil)
	_ caddy.Provisioner = (*StorageLoader)(nil)
)
