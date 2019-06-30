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
	"io/ioutil"

	"github.com/caddyserver/caddy"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "tls.certificates.load_files",
		New:  func() interface{} { return fileLoader{} },
	})
}

// fileLoader loads certificates and their associated keys from disk.
type fileLoader []CertKeyFilePair

// CertKeyFilePair pairs certificate and key file names along with their
// encoding format so that they can be loaded from disk.
type CertKeyFilePair struct {
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Format      string   `json:"format,omitempty"` // "pem" is default
	Tags        []string `json:"tags,omitempty"`
}

// LoadCertificates returns the certificates to be loaded by fl.
func (fl fileLoader) LoadCertificates() ([]Certificate, error) {
	var certs []Certificate
	for _, pair := range fl {
		certData, err := ioutil.ReadFile(pair.Certificate)
		if err != nil {
			return nil, err
		}
		keyData, err := ioutil.ReadFile(pair.Key)
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
var _ CertificateLoader = (fileLoader)(nil)
