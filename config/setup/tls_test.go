package setup

import (
	"crypto/tls"
	"testing"
)

func TestTLSParseBasic(t *testing.T) {
	c := newTestController(`tls cert.pem key.pem`)

	_, err := TLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	// Basic checks
	if c.TLS.Certificate != "cert.pem" {
		t.Errorf("Expected certificate arg to be 'cert.pem', was '%s'", c.TLS.Certificate)
	}
	if c.TLS.Key != "key.pem" {
		t.Errorf("Expected key arg to be 'key.pem', was '%s'", c.TLS.Key)
	}
	if !c.TLS.Enabled {
		t.Error("Expected TLS Enabled=true, but was false")
	}

	// Security defaults
	if c.TLS.ProtocolMinVersion != tls.VersionTLS10 {
		t.Errorf("Expected 'tls1.0 (0x0301)' as ProtocolMinVersion, got %#v", c.TLS.ProtocolMinVersion)
	}
	if c.TLS.ProtocolMaxVersion != tls.VersionTLS12 {
		t.Errorf("Expected 'tls1.2 (0x0303)' as ProtocolMaxVersion, got %v", c.TLS.ProtocolMaxVersion)
	}
	if c.TLS.CacheSize != 64 {
		t.Errorf("Expected CacheSize 64, got %v", c.TLS.CacheSize)
	}

	// Cipher checks
	expectedCiphers := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_FALLBACK_SCSV,
	}

	// Ensure count is correct (plus one for TLS_FALLBACK_SCSV)
	if len(c.TLS.Ciphers) != len(supportedCiphers)+1 {
		t.Errorf("Expected %v Ciphers (including TLS_FALLBACK_SCSV), got %v",
			len(supportedCiphers)+1, len(c.TLS.Ciphers))
	}

	// Ensure ordering is correct
	for i, actual := range c.TLS.Ciphers {
		if actual != expectedCiphers[i] {
			t.Errorf("Expected cipher in position %d to be %0x, got %0x", i, expectedCiphers[i], actual)
		}
	}

	if !c.TLS.PreferServerCipherSuites {
		t.Error("Expected PreferServerCipherSuites = true, but was false")
	}
}

func TestTLSParseIncompleteParams(t *testing.T) {
	c := newTestController(`tls`)

	_, err := TLS(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}

	c = newTestController(`tls cert.key`)

	_, err = TLS(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}
}

func TestTLSParseWithOptionalParams(t *testing.T) {
	params := `tls cert.crt cert.key {
            protocols ssl3.0 tls1.2
            ciphers RSA-3DES-EDE-CBC-SHA RSA-AES256-CBC-SHA ECDHE-RSA-AES128-GCM-SHA256
            cache 128
        }`
	c := newTestController(params)

	_, err := TLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if c.TLS.ProtocolMinVersion != tls.VersionSSL30 {
		t.Errorf("Expected 'ssl3.0 (0x0300)' as ProtocolMinVersion, got %#v", c.TLS.ProtocolMinVersion)
	}

	if c.TLS.ProtocolMaxVersion != tls.VersionTLS12 {
		t.Errorf("Expected 'tls1.2 (0x0302)' as ProtocolMaxVersion, got %#v", c.TLS.ProtocolMaxVersion)
	}

	if len(c.TLS.Ciphers)-1 != 3 {
		t.Errorf("Expected 3 Ciphers (not including TLS_FALLBACK_SCSV), got %v", len(c.TLS.Ciphers))
	}

	if c.TLS.CacheSize != 128 {
		t.Errorf("Expected CacheSize 128, got %v", c.TLS.CacheSize)
	}
}

func TestTLSParseWithWrongOptionalParams(t *testing.T) {
	params := `tls cert.crt cert.key {
            cache a
        }`
	c := newTestController(params)
	_, err := TLS(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}

	// Test protocols wrong params
	params = `tls cert.crt cert.key {
			protocols ssl tls
		}`
	c = newTestController(params)
	_, err = TLS(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}

	// Test ciphers wrong params
	params = `tls cert.crt cert.key {
			ciphers not-valid-cipher
		}`
	c = newTestController(params)
	_, err = TLS(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}
}
