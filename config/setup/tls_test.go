package setup

import (
	"crypto/tls"
	"testing"
)

func TestTLSParseNoOptional(t *testing.T) {
	c := newTestController(`tls cert.crt cert.key`)

	_, err := TLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if len(c.TLS.Ciphers) != len(supportedCiphers) {
		t.Errorf("Expected %v Ciphers, got %v", len(supportedCiphers), len(c.TLS.Ciphers))
	}

	if c.TLS.ProtocolMinVersion != tls.VersionTLS11 {
		t.Errorf("Expected 'tls1.1 (0x0302)' as ProtocolMinVersion, got %#v", c.TLS.ProtocolMinVersion)
	}

	if c.TLS.ProtocolMaxVersion != tls.VersionTLS12 {
		t.Errorf("Expected 'tls1.2 (0x0303)' as ProtocolMaxVersion, got %v", c.TLS.ProtocolMaxVersion)
	}

	if c.TLS.CacheSize != 64 {
		t.Errorf("Expected CacheSize 64, got %v", c.TLS.CacheSize)
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

	if len(c.TLS.Ciphers) != 3 {
		t.Errorf("Expected 3 Ciphers, got %v", len(c.TLS.Ciphers))
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
