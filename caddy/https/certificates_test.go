package https

import "testing"

func TestUnexportedGetCertificate(t *testing.T) {
	defer func() { certCache = make(map[string]Certificate) }()

	// When cache is empty
	if _, matched, defaulted := getCertificate("example.com"); matched || defaulted {
		t.Errorf("Got a certificate when cache was empty; matched=%v, defaulted=%v", matched, defaulted)
	}

	// When cache has one certificate in it (also is default)
	defaultCert := Certificate{Names: []string{"example.com", ""}}
	certCache[""] = defaultCert
	certCache["example.com"] = defaultCert
	if cert, matched, defaulted := getCertificate("Example.com"); !matched || defaulted || cert.Names[0] != "example.com" {
		t.Errorf("Didn't get a cert for 'Example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}
	if cert, matched, defaulted := getCertificate(""); !matched || defaulted || cert.Names[0] != "example.com" {
		t.Errorf("Didn't get a cert for '' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}

	// When retrieving wildcard certificate
	certCache["*.example.com"] = Certificate{Names: []string{"*.example.com"}}
	if cert, matched, defaulted := getCertificate("sub.example.com"); !matched || defaulted || cert.Names[0] != "*.example.com" {
		t.Errorf("Didn't get wildcard cert for 'sub.example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}

	// When no certificate matches, the default is returned
	if cert, matched, defaulted := getCertificate("nomatch"); matched || !defaulted {
		t.Errorf("Expected matched=false, defaulted=true; but got matched=%v, defaulted=%v (cert: %v)", matched, defaulted, cert)
	} else if cert.Names[0] != "example.com" {
		t.Errorf("Expected default cert, got: %v", cert)
	}
}

func TestCacheCertificate(t *testing.T) {
	defer func() { certCache = make(map[string]Certificate) }()

	cacheCertificate(Certificate{Names: []string{"example.com", "sub.example.com"}})
	if _, ok := certCache["example.com"]; !ok {
		t.Error("Expected first cert to be cached by key 'example.com', but it wasn't")
	}
	if _, ok := certCache["sub.example.com"]; !ok {
		t.Error("Expected first cert to be cached by key 'sub.exmaple.com', but it wasn't")
	}
	if cert, ok := certCache[""]; !ok || cert.Names[2] != "" {
		t.Error("Expected first cert to be cached additionally as the default certificate with empty name added, but it wasn't")
	}

	cacheCertificate(Certificate{Names: []string{"example2.com"}})
	if _, ok := certCache["example2.com"]; !ok {
		t.Error("Expected second cert to be cached by key 'exmaple2.com', but it wasn't")
	}
	if cert, ok := certCache[""]; ok && cert.Names[0] == "example2.com" {
		t.Error("Expected second cert to NOT be cached as default, but it was")
	}
}
