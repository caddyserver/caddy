package https

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/mholt/caddy/caddy/setup"
	"github.com/xenolf/lego/acme"
)

func TestMain(m *testing.M) {
	// Write test certificates to disk before tests, and clean up
	// when we're done.
	err := ioutil.WriteFile(certFile, testCert, 0644)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(keyFile, testKey, 0644)
	if err != nil {
		os.Remove(certFile)
		log.Fatal(err)
	}

	result := m.Run()

	os.Remove(certFile)
	os.Remove(keyFile)
	os.Exit(result)
}

func TestSetupParseBasic(t *testing.T) {
	c := setup.NewTestController(`tls ` + certFile + ` ` + keyFile + ``)

	_, err := Setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	// Basic checks
	if !c.TLS.Manual {
		t.Error("Expected TLS Manual=true, but was false")
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

	// KeyType default
	if KeyType != acme.RSA2048 {
		t.Errorf("Expected '2048' as KeyType, got %#v", KeyType)
	}

	// Cipher checks
	expectedCiphers := []uint16{
		tls.TLS_FALLBACK_SCSV,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}

	// Ensure count is correct (plus one for TLS_FALLBACK_SCSV)
	if len(c.TLS.Ciphers) != len(expectedCiphers) {
		t.Errorf("Expected %v Ciphers (including TLS_FALLBACK_SCSV), got %v",
			len(expectedCiphers), len(c.TLS.Ciphers))
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

func TestSetupParseIncompleteParams(t *testing.T) {
	// Using tls without args is an error because it's unnecessary.
	c := setup.NewTestController(`tls`)
	_, err := Setup(c)
	if err == nil {
		t.Error("Expected an error, but didn't get one")
	}
}

func TestSetupParseWithOptionalParams(t *testing.T) {
	params := `tls ` + certFile + ` ` + keyFile + ` {
            protocols ssl3.0 tls1.2
            ciphers RSA-AES256-CBC-SHA ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384
        }`
	c := setup.NewTestController(params)

	_, err := Setup(c)
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
		t.Errorf("Expected 3 Ciphers (not including TLS_FALLBACK_SCSV), got %v", len(c.TLS.Ciphers)-1)
	}
}

func TestSetupDefaultWithOptionalParams(t *testing.T) {
	params := `tls {
            ciphers RSA-3DES-EDE-CBC-SHA
        }`
	c := setup.NewTestController(params)

	_, err := Setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	if len(c.TLS.Ciphers)-1 != 1 {
		t.Errorf("Expected 1 ciphers (not including TLS_FALLBACK_SCSV), got %v", len(c.TLS.Ciphers)-1)
	}
}

// TODO: If we allow this... but probably not a good idea.
// func TestSetupDisableHTTPRedirect(t *testing.T) {
// 	c := NewTestController(`tls {
// 	    allow_http
// 	}`)
// 	_, err := TLS(c)
// 	if err != nil {
// 		t.Errorf("Expected no error, but got %v", err)
// 	}
// 	if !c.TLS.DisableHTTPRedir {
// 		t.Error("Expected HTTP redirect to be disabled, but it wasn't")
// 	}
// }

func TestSetupParseWithWrongOptionalParams(t *testing.T) {
	// Test protocols wrong params
	params := `tls ` + certFile + ` ` + keyFile + ` {
			protocols ssl tls
		}`
	c := setup.NewTestController(params)
	_, err := Setup(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}

	// Test ciphers wrong params
	params = `tls ` + certFile + ` ` + keyFile + ` {
			ciphers not-valid-cipher
		}`
	c = setup.NewTestController(params)
	_, err = Setup(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}

	// Test key_type wrong params
	params = `tls {
			key_type ab123
		}`
	c = setup.NewTestController(params)
	_, err = Setup(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}
}

func TestSetupParseWithClientAuth(t *testing.T) {
	// Test missing client cert file
	params := `tls ` + certFile + ` ` + keyFile + ` {
			clients
		}`
	c := setup.NewTestController(params)
	_, err := Setup(c)
	if err == nil {
		t.Errorf("Expected an error, but no error returned")
	}

	noCAs, twoCAs := []string{}, []string{"client_ca.crt", "client2_ca.crt"}
	for caseNumber, caseData := range []struct {
		params         string
		clientAuthType tls.ClientAuthType
		expectedErr    bool
		expectedCAs    []string
	}{
		{"", tls.NoClientCert, false, noCAs},
		{`tls ` + certFile + ` ` + keyFile + ` {
			clients client_ca.crt client2_ca.crt
		}`, tls.RequireAndVerifyClientCert, false, twoCAs},
		// now come modifier
		{`tls ` + certFile + ` ` + keyFile + ` {
			clients request
		}`, tls.RequestClientCert, false, noCAs},
		{`tls ` + certFile + ` ` + keyFile + ` {
			clients require
		}`, tls.RequireAnyClientCert, false, noCAs},
		{`tls ` + certFile + ` ` + keyFile + ` {
			clients verify_if_given client_ca.crt client2_ca.crt
		}`, tls.VerifyClientCertIfGiven, false, twoCAs},
		{`tls ` + certFile + ` ` + keyFile + ` {
			clients verify_if_given
		}`, tls.VerifyClientCertIfGiven, true, noCAs},
	} {
		c := setup.NewTestController(caseData.params)
		_, err := Setup(c)
		if caseData.expectedErr {
			if err == nil {
				t.Errorf("In case %d: Expected an error, got: %v", caseNumber, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("In case %d: Expected no errors, got: %v", caseNumber, err)
		}

		if caseData.clientAuthType != c.TLS.ClientAuth {
			t.Errorf("In case %d: Expected TLS client auth type %v, got: %v",
				caseNumber, caseData.clientAuthType, c.TLS.ClientAuth)
		}

		if count := len(c.TLS.ClientCerts); count < len(caseData.expectedCAs) {
			t.Fatalf("In case %d: Expected %d client certs, had %d", caseNumber, len(caseData.expectedCAs), count)
		}

		for idx, expected := range caseData.expectedCAs {
			if actual := c.TLS.ClientCerts[idx]; actual != expected {
				t.Errorf("In case %d: Expected %dth client cert file to be '%s', but was '%s'",
					caseNumber, idx, expected, actual)
			}
		}
	}
}

func TestSetupParseWithKeyType(t *testing.T) {
	params := `tls {
            key_type p384
        }`
	c := setup.NewTestController(params)

	_, err := Setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if KeyType != acme.EC384 {
		t.Errorf("Expected 'P384' as KeyType, got %#v", KeyType)
	}
}

const (
	certFile = "test_cert.pem"
	keyFile  = "test_key.pem"
)

var testCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBkjCCATmgAwIBAgIJANfFCBcABL6LMAkGByqGSM49BAEwFDESMBAGA1UEAxMJ
bG9jYWxob3N0MB4XDTE2MDIxMDIyMjAyNFoXDTE4MDIwOTIyMjAyNFowFDESMBAG
A1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs22MtnG7
9K1mvIyjEO9GLx7BFD0tBbGnwQ0VPsuCxC6IeVuXbQDLSiVQvFZ6lUszTlczNxVk
pEfqrM6xAupB7qN1MHMwHQYDVR0OBBYEFHxYDvAxUwL4XrjPev6qZ/BiLDs5MEQG
A1UdIwQ9MDuAFHxYDvAxUwL4XrjPev6qZ/BiLDs5oRikFjAUMRIwEAYDVQQDEwls
b2NhbGhvc3SCCQDXxQgXAAS+izAMBgNVHRMEBTADAQH/MAkGByqGSM49BAEDSAAw
RQIgRvBqbyJM2JCJqhA1FmcoZjeMocmhxQHTt1c+1N2wFUgCIQDtvrivbBPA688N
Qh3sMeAKNKPsx5NxYdoWuu9KWcKz9A==
-----END CERTIFICATE-----
`)

var testKey = []byte(`-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGLtRmwzYVcrH3J0BnzYbGPdWVF10i9p6mxkA4+b2fURoAoGCCqGSM49
AwEHoUQDQgAEs22MtnG79K1mvIyjEO9GLx7BFD0tBbGnwQ0VPsuCxC6IeVuXbQDL
SiVQvFZ6lUszTlczNxVkpEfqrM6xAupB7g==
-----END EC PRIVATE KEY-----
`)
