// Copyright 2015 Light Code Labs, LLC
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
	"crypto/x509"
	"testing"
)

func TestGetCertificate(t *testing.T) {
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	helloSub := &tls.ClientHelloInfo{ServerName: "sub.example.com"}
	helloNoSNI := &tls.ClientHelloInfo{}
	helloNoMatch := &tls.ClientHelloInfo{ServerName: "nomatch"}

	// When cache is empty
	if cert, err := cfg.GetCertificate(hello); err == nil {
		t.Errorf("GetCertificate should return error when cache is empty, got: %v", cert)
	}
	if cert, err := cfg.GetCertificate(helloNoSNI); err == nil {
		t.Errorf("GetCertificate should return error when cache is empty even if server name is blank, got: %v", cert)
	}

	// When cache has one certificate in it
	firstCert := Certificate{Names: []string{"example.com"}, Certificate: tls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"example.com"}}}}
	cfg.cacheCertificate(firstCert)
	if cert, err := cfg.GetCertificate(hello); err != nil {
		t.Errorf("Got an error but shouldn't have, when cert exists in cache: %v", err)
	} else if cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("Got wrong certificate with exact match; expected 'example.com', got: %v", cert)
	}
	if _, err := cfg.GetCertificate(helloNoSNI); err != nil {
		t.Errorf("Got an error with no SNI but shouldn't have, when cert exists in cache: %v", err)
	}

	// When retrieving wildcard certificate
	wildcardCert := Certificate{
		Names:       []string{"*.example.com"},
		Certificate: tls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"*.example.com"}}},
		Hash:        "(don't overwrite the first one)",
	}
	cfg.cacheCertificate(wildcardCert)
	if cert, err := cfg.GetCertificate(helloSub); err != nil {
		t.Errorf("Didn't get wildcard cert, got: cert=%v, err=%v ", cert, err)
	} else if cert.Leaf.DNSNames[0] != "*.example.com" {
		t.Errorf("Got wrong certificate, expected wildcard: %v", cert)
	}

	// When cache is NOT empty but there's no SNI
	if cert, err := cfg.GetCertificate(helloNoSNI); err != nil {
		t.Errorf("Expected random certificate with no error when no SNI, got err: %v", err)
	} else if cert == nil || len(cert.Leaf.DNSNames) == 0 {
		t.Errorf("Expected random cert with no matches, got: %v", cert)
	}

	// When no certificate matches, raise an alert
	if _, err := cfg.GetCertificate(helloNoMatch); err == nil {
		t.Errorf("Expected an error when no certificate matched the SNI, got: %v", err)
	}
}
