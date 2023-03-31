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

package caddypki

import (
	"crypto"
	"crypto/x509"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
)

func generateRoot(commonName string) (*x509.Certificate, crypto.Signer, error) {
	template, signer, err := newCert(commonName, x509util.DefaultRootTemplate, defaultRootLifetime)
	if err != nil {
		return nil, nil, err
	}
	root, err := x509util.CreateCertificate(template, template, signer.Public(), signer)
	if err != nil {
		return nil, nil, err
	}
	return root, signer, nil
}

func generateIntermediate(commonName string, rootCrt *x509.Certificate, rootKey crypto.Signer, lifetime time.Duration) (*x509.Certificate, crypto.Signer, error) {
	template, signer, err := newCert(commonName, x509util.DefaultIntermediateTemplate, lifetime)
	if err != nil {
		return nil, nil, err
	}
	intermediate, err := x509util.CreateCertificate(template, rootCrt, signer.Public(), rootKey)
	if err != nil {
		return nil, nil, err
	}
	return intermediate, signer, nil
}

func newCert(commonName, templateName string, lifetime time.Duration) (cert *x509.Certificate, signer crypto.Signer, err error) {
	signer, err = keyutil.GenerateDefaultSigner()
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509util.CreateCertificateRequest(commonName, []string{}, signer)
	if err != nil {
		return nil, nil, err
	}
	template, err := x509util.NewCertificate(csr, x509util.WithTemplate(templateName, x509util.CreateTemplateData(commonName, []string{})))
	if err != nil {
		return nil, nil, err
	}

	cert = template.GetCertificate()
	cert.NotBefore = time.Now().Truncate(time.Second)
	cert.NotAfter = cert.NotBefore.Add(lifetime)
	return cert, signer, nil
}
