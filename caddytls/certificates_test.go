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

import "testing"

func TestUnexportedGetCertificate(t *testing.T) {
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}

	// When cache is empty
	if _, matched, defaulted := cfg.getCertificate("example.com"); matched || defaulted {
		t.Errorf("Got a certificate when cache was empty; matched=%v, defaulted=%v", matched, defaulted)
	}

	// When cache has one certificate in it
	firstCert := Certificate{Names: []string{"example.com"}}
	certCache.cache["0xdeadbeef"] = firstCert
	cfg.Certificates["example.com"] = "0xdeadbeef"
	if cert, matched, defaulted := cfg.getCertificate("Example.com"); !matched || defaulted || cert.Names[0] != "example.com" {
		t.Errorf("Didn't get a cert for 'Example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}
	if cert, matched, defaulted := cfg.getCertificate("example.com"); !matched || defaulted || cert.Names[0] != "example.com" {
		t.Errorf("Didn't get a cert for 'example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}

	// When retrieving wildcard certificate
	certCache.cache["0xb01dface"] = Certificate{Names: []string{"*.example.com"}}
	cfg.Certificates["*.example.com"] = "0xb01dface"
	if cert, matched, defaulted := cfg.getCertificate("sub.example.com"); !matched || defaulted || cert.Names[0] != "*.example.com" {
		t.Errorf("Didn't get wildcard cert for 'sub.example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}

	// When no certificate matches and SNI is provided, return no certificate (should be TLS alert)
	if cert, matched, defaulted := cfg.getCertificate("nomatch"); matched || defaulted {
		t.Errorf("Expected matched=false, defaulted=false; but got matched=%v, defaulted=%v (cert: %v)", matched, defaulted, cert)
	}

	// When no certificate matches and SNI is NOT provided, a random is returned
	if cert, matched, defaulted := cfg.getCertificate(""); matched || !defaulted {
		t.Errorf("Expected matched=false, defaulted=true; but got matched=%v, defaulted=%v (cert: %v)", matched, defaulted, cert)
	}
}

func TestCacheCertificate(t *testing.T) {
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}

	cfg.cacheCertificate(Certificate{Names: []string{"example.com", "sub.example.com"}, Hash: "foobar"})
	if len(certCache.cache) != 1 {
		t.Errorf("Expected length of certificate cache to be 1")
	}
	if _, ok := certCache.cache["foobar"]; !ok {
		t.Error("Expected first cert to be cached by key 'foobar', but it wasn't")
	}
	if _, ok := cfg.Certificates["example.com"]; !ok {
		t.Error("Expected first cert to be keyed by 'example.com', but it wasn't")
	}
	if _, ok := cfg.Certificates["sub.example.com"]; !ok {
		t.Error("Expected first cert to be keyed by 'sub.example.com', but it wasn't")
	}

	// different config, but using same cache; and has cert with overlapping name,
	// but different hash
	cfg2 := &Config{Certificates: make(map[string]string), certCache: certCache}
	cfg2.cacheCertificate(Certificate{Names: []string{"example.com"}, Hash: "barbaz"})
	if _, ok := certCache.cache["barbaz"]; !ok {
		t.Error("Expected second cert to be cached by key 'barbaz.com', but it wasn't")
	}
	if hash, ok := cfg2.Certificates["example.com"]; !ok {
		t.Error("Expected second cert to be keyed by 'example.com', but it wasn't")
	} else if hash != "barbaz" {
		t.Errorf("Expected second cert to map to 'barbaz' but it was %s instead", hash)
	}
}
