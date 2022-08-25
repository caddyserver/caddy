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

	"github.com/smallstep/cli/crypto/x509util"
)

func generateRoot(commonName string) (rootCrt *x509.Certificate, privateKey any, err error) {
	rootProfile, err := x509util.NewRootProfile(commonName)
	if err != nil {
		return
	}
	rootProfile.Subject().NotAfter = time.Now().Add(defaultRootLifetime) // TODO: make configurable
	return newCert(rootProfile)
}

func generateIntermediate(commonName string, rootCrt *x509.Certificate, rootKey crypto.PrivateKey) (cert *x509.Certificate, privateKey crypto.PrivateKey, err error) {
	interProfile, err := x509util.NewIntermediateProfile(commonName, rootCrt, rootKey)
	if err != nil {
		return
	}
	interProfile.Subject().NotAfter = time.Now().Add(defaultIntermediateLifetime) // TODO: make configurable
	return newCert(interProfile)
}

func newCert(profile x509util.Profile) (cert *x509.Certificate, privateKey crypto.PrivateKey, err error) {
	certBytes, err := profile.CreateCertificate()
	if err != nil {
		return
	}
	privateKey = profile.SubjectPrivateKey()
	cert, err = x509.ParseCertificate(certBytes)
	return
}
