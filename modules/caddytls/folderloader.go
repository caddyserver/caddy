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
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(FolderLoader{})
}

// FolderLoader loads certificates and their associated keys from disk
// by recursively walking the specified directories, looking for PEM
// files which contain both a certificate and a key.
type FolderLoader []string

// CaddyModule returns the Caddy module information.
func (FolderLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.load_folders",
		New: func() caddy.Module { return new(FolderLoader) },
	}
}

// Provision implements caddy.Provisioner.
func (fl FolderLoader) Provision(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	for k, path := range fl {
		fl[k] = repl.ReplaceKnown(path, "")
	}
	return nil
}

// LoadCertificates loads all the certificates+keys in the directories
// listed in fl from all files ending with .pem. This method of loading
// certificates expects the certificate and key to be bundled into the
// same file.
func (fl FolderLoader) LoadCertificates() ([]Certificate, error) {
	var certs []Certificate
	for _, dir := range fl {
		err := filepath.Walk(dir, func(fpath string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("unable to traverse into path: %s", fpath)
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(info.Name()), ".pem") {
				return nil
			}

			bundle, err := os.ReadFile(fpath)
			if err != nil {
				return err
			}
			cert, err := tlsCertFromCertAndKeyPEMBundle(bundle)
			if err != nil {
				return fmt.Errorf("%s: %w", fpath, err)
			}

			certs = append(certs, Certificate{Certificate: cert})

			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return certs, nil
}

func tlsCertFromCertAndKeyPEMBundle(bundle []byte) (tls.Certificate, error) {
	certBuilder, keyBuilder := new(bytes.Buffer), new(bytes.Buffer)
	var foundKey bool // use only the first key in the file

	for {
		// Decode next block so we can see what type it is
		var derBlock *pem.Block
		derBlock, bundle = pem.Decode(bundle)
		if derBlock == nil {
			break
		}

		if derBlock.Type == "CERTIFICATE" {
			// Re-encode certificate as PEM, appending to certificate chain
			if err := pem.Encode(certBuilder, derBlock); err != nil {
				return tls.Certificate{}, err
			}
		} else if derBlock.Type == "EC PARAMETERS" {
			// EC keys generated from openssl can be composed of two blocks:
			// parameters and key (parameter block should come first)
			if !foundKey {
				// Encode parameters
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}

				// Key must immediately follow
				derBlock, bundle = pem.Decode(bundle)
				if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
					return tls.Certificate{}, fmt.Errorf("expected elliptic private key to immediately follow EC parameters")
				}
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
			// RSA key
			if !foundKey {
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else {
			return tls.Certificate{}, fmt.Errorf("unrecognized PEM block type: %s", derBlock.Type)
		}
	}

	certPEMBytes, keyPEMBytes := certBuilder.Bytes(), keyBuilder.Bytes()
	if len(certPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("failed to parse PEM data")
	}
	if len(keyPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("no private key block found")
	}

	// if the start of the key file looks like an encrypted private key,
	// reject it with a helpful error message
	if strings.HasPrefix(string(keyPEMBytes[:40]), "ENCRYPTED") {
		return tls.Certificate{}, fmt.Errorf("encrypted private keys are not supported; please decrypt the key first")
	}

	cert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("making X509 key pair: %v", err)
	}

	return cert, nil
}

var (
	_ CertificateLoader = (FolderLoader)(nil)
	_ caddy.Provisioner = (FolderLoader)(nil)
)
