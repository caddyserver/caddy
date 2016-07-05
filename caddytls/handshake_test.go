package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestGetCertificate(t *testing.T) {
	defer func() { certCache = make(map[string]Certificate) }()

	cg := make(configGroup)

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	helloSub := &tls.ClientHelloInfo{ServerName: "sub.example.com"}
	helloNoSNI := &tls.ClientHelloInfo{}
	helloNoMatch := &tls.ClientHelloInfo{ServerName: "nomatch"}

	// When cache is empty
	if cert, err := cg.GetCertificate(hello); err == nil {
		t.Errorf("GetCertificate should return error when cache is empty, got: %v", cert)
	}
	if cert, err := cg.GetCertificate(helloNoSNI); err == nil {
		t.Errorf("GetCertificate should return error when cache is empty even if server name is blank, got: %v", cert)
	}

	// When cache has one certificate in it (also is default)
	defaultCert := Certificate{Names: []string{"example.com", ""}, Certificate: tls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"example.com"}}}}
	certCache[""] = defaultCert
	certCache["example.com"] = defaultCert
	if cert, err := cg.GetCertificate(hello); err != nil {
		t.Errorf("Got an error but shouldn't have, when cert exists in cache: %v", err)
	} else if cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("Got wrong certificate with exact match; expected 'example.com', got: %v", cert)
	}
	if cert, err := cg.GetCertificate(helloNoSNI); err != nil {
		t.Errorf("Got an error with no SNI but shouldn't have, when cert exists in cache: %v", err)
	} else if cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("Got wrong certificate for no SNI; expected 'example.com' as default, got: %v", cert)
	}

	// When retrieving wildcard certificate
	certCache["*.example.com"] = Certificate{Names: []string{"*.example.com"}, Certificate: tls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"*.example.com"}}}}
	if cert, err := cg.GetCertificate(helloSub); err != nil {
		t.Errorf("Didn't get wildcard cert, got: cert=%v, err=%v ", cert, err)
	} else if cert.Leaf.DNSNames[0] != "*.example.com" {
		t.Errorf("Got wrong certificate, expected wildcard: %v", cert)
	}

	// When no certificate matches, the default is returned
	if cert, err := cg.GetCertificate(helloNoMatch); err != nil {
		t.Errorf("Expected default certificate with no error when no matches, got err: %v", err)
	} else if cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("Expected default cert with no matches, got: %v", cert)
	}
}
