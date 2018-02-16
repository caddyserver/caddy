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
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/mholt/caddy"
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
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}

	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c := caddy.NewTestController("", `tls `+certFile+` `+keyFile+``)
	c.Set(CertCacheInstStorageKey, certCache)

	err := setupTLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	// Basic checks
	if !cfg.Manual {
		t.Error("Expected TLS Manual=true, but was false")
	}
	if !cfg.Enabled {
		t.Error("Expected TLS Enabled=true, but was false")
	}

	// Security defaults
	if cfg.ProtocolMinVersion != tls.VersionTLS11 {
		t.Errorf("Expected 'tls1.1 (0x0302)' as ProtocolMinVersion, got %#v", cfg.ProtocolMinVersion)
	}
	if cfg.ProtocolMaxVersion != tls.VersionTLS12 {
		t.Errorf("Expected 'tls1.2 (0x0303)' as ProtocolMaxVersion, got %v", cfg.ProtocolMaxVersion)
	}

	// Cipher checks
	expectedCiphers := append([]uint16{tls.TLS_FALLBACK_SCSV}, getPreferredDefaultCiphers()...)

	// Ensure count is correct (plus one for TLS_FALLBACK_SCSV)
	if len(cfg.Ciphers) != len(expectedCiphers) {
		t.Errorf("Expected %v Ciphers (including TLS_FALLBACK_SCSV), got %v",
			len(expectedCiphers), len(cfg.Ciphers))
	}

	// Ensure ordering is correct
	for i, actual := range cfg.Ciphers {
		if actual != expectedCiphers[i] {
			t.Errorf("Expected cipher in position %d to be %0x, got %0x", i, expectedCiphers[i], actual)
		}
	}

	if !cfg.PreferServerCipherSuites {
		t.Error("Expected PreferServerCipherSuites = true, but was false")
	}

	if len(cfg.ALPN) != 0 {
		t.Error("Expected ALPN empty by default")
	}

	// Ensure curve count is correct
	if len(cfg.CurvePreferences) != len(defaultCurves) {
		t.Errorf("Expected %v Curves, got %v", len(defaultCurves), len(cfg.CurvePreferences))
	}

	// Ensure curve ordering is correct
	for i, actual := range cfg.CurvePreferences {
		if actual != defaultCurves[i] {
			t.Errorf("Expected curve in position %d to be %0x, got %0x", i, defaultCurves[i], actual)
		}
	}
}

func TestSetupParseIncompleteParams(t *testing.T) {
	// Using tls without args is an error because it's unnecessary.
	c := caddy.NewTestController("", `tls`)
	err := setupTLS(c)
	if err == nil {
		t.Error("Expected an error, but didn't get one")
	}
}

func TestSetupParseWithOptionalParams(t *testing.T) {
	params := `tls ` + certFile + ` ` + keyFile + ` {
            protocols tls1.0 tls1.2
            ciphers RSA-AES256-CBC-SHA ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384
            must_staple
            alpn http/1.1
        }`
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}

	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c := caddy.NewTestController("", params)
	c.Set(CertCacheInstStorageKey, certCache)

	err := setupTLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if cfg.ProtocolMinVersion != tls.VersionTLS10 {
		t.Errorf("Expected 'tls1.0 (0x0301)' as ProtocolMinVersion, got %#v", cfg.ProtocolMinVersion)
	}

	if cfg.ProtocolMaxVersion != tls.VersionTLS12 {
		t.Errorf("Expected 'tls1.2 (0x0303)' as ProtocolMaxVersion, got %#v", cfg.ProtocolMaxVersion)
	}

	if len(cfg.Ciphers)-1 != 3 {
		t.Errorf("Expected 3 Ciphers (not including TLS_FALLBACK_SCSV), got %v", len(cfg.Ciphers)-1)
	}

	if !cfg.MustStaple {
		t.Error("Expected must staple to be true")
	}

	if len(cfg.ALPN) != 1 || cfg.ALPN[0] != "http/1.1" {
		t.Errorf("Expected ALPN to contain only 'http/1.1' but got: %v", cfg.ALPN)
	}
}

func TestSetupDefaultWithOptionalParams(t *testing.T) {
	params := `tls {
            ciphers RSA-3DES-EDE-CBC-SHA
        }`
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c := caddy.NewTestController("", params)
	c.Set(CertCacheInstStorageKey, certCache)

	err := setupTLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	if len(cfg.Ciphers)-1 != 1 {
		t.Errorf("Expected 1 ciphers (not including TLS_FALLBACK_SCSV), got %v", len(cfg.Ciphers)-1)
	}
}

func TestSetupParseWithWrongOptionalParams(t *testing.T) {
	// Test protocols wrong params
	params := `tls ` + certFile + ` ` + keyFile + ` {
			protocols ssl tls
		}`
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c := caddy.NewTestController("", params)
	c.Set(CertCacheInstStorageKey, certCache)

	err := setupTLS(c)
	if err == nil {
		t.Errorf("Expected errors, but no error returned")
	}

	// Test ciphers wrong params
	params = `tls ` + certFile + ` ` + keyFile + ` {
			ciphers not-valid-cipher
		}`
	cfg = new(Config)
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c = caddy.NewTestController("", params)
	c.Set(CertCacheInstStorageKey, certCache)
	err = setupTLS(c)
	if err == nil {
		t.Error("Expected errors, but no error returned")
	}

	// Test key_type wrong params
	params = `tls {
			key_type ab123
		}`
	cfg = new(Config)
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c = caddy.NewTestController("", params)
	err = setupTLS(c)
	if err == nil {
		t.Error("Expected errors, but no error returned")
	}

	// Test curves wrong params
	params = `tls {
			curves ab123, cd456, ef789
		}`
	cfg = new(Config)
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c = caddy.NewTestController("", params)
	c.Set(CertCacheInstStorageKey, certCache)
	err = setupTLS(c)
	if err == nil {
		t.Error("Expected errors, but no error returned")
	}
}

func TestSetupParseWithClientAuth(t *testing.T) {
	// Test missing client cert file
	params := `tls ` + certFile + ` ` + keyFile + ` {
			clients
		}`
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c := caddy.NewTestController("", params)
	err := setupTLS(c)
	if err == nil {
		t.Error("Expected an error, but no error returned")
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
		certCache := &certificateCache{cache: make(map[string]Certificate)}
		cfg := &Config{Certificates: make(map[string]string), certCache: certCache}
		RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
		c := caddy.NewTestController("", caseData.params)
		c.Set(CertCacheInstStorageKey, certCache)
		err := setupTLS(c)
		if caseData.expectedErr {
			if err == nil {
				t.Errorf("In case %d: Expected an error, got: %v", caseNumber, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("In case %d: Expected no errors, got: %v", caseNumber, err)
		}

		if caseData.clientAuthType != cfg.ClientAuth {
			t.Errorf("In case %d: Expected TLS client auth type %v, got: %v",
				caseNumber, caseData.clientAuthType, cfg.ClientAuth)
		}

		if count := len(cfg.ClientCerts); count < len(caseData.expectedCAs) {
			t.Fatalf("In case %d: Expected %d client certs, had %d", caseNumber, len(caseData.expectedCAs), count)
		}

		for idx, expected := range caseData.expectedCAs {
			if actual := cfg.ClientCerts[idx]; actual != expected {
				t.Errorf("In case %d: Expected %dth client cert file to be '%s', but was '%s'",
					caseNumber, idx, expected, actual)
			}
		}
	}
}

func TestSetupParseWithCAUrl(t *testing.T) {
	testURL := "https://acme-staging.api.letsencrypt.org/directory"
	for caseNumber, caseData := range []struct {
		params        string
		expectedErr   bool
		expectedCAUrl string
	}{
		// Test working case
		{`tls {
				ca ` + testURL + `
			}`, false, testURL},
		// Test too few args
		{`tls {
				ca
			}`, true, ""},
		// Test too many args
		{`tls {
				ca 1 2
			}`, true, ""},
	} {
		certCache := &certificateCache{cache: make(map[string]Certificate)}
		cfg := &Config{Certificates: make(map[string]string), certCache: certCache}
		RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
		c := caddy.NewTestController("", caseData.params)
		c.Set(CertCacheInstStorageKey, certCache)
		err := setupTLS(c)
		if caseData.expectedErr {
			if err == nil {
				t.Errorf("In case %d: Expected an error, got: %v", caseNumber, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("In case %d: Expected no errors, got: %v", caseNumber, err)
		}

		if cfg.CAUrl != caseData.expectedCAUrl {
			t.Errorf("Expected '%v' as CAUrl, got %#v", caseData.expectedCAUrl, cfg.CAUrl)
		}
	}
}

func TestSetupParseWithKeyType(t *testing.T) {
	params := `tls {
            key_type p384
        }`
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c := caddy.NewTestController("", params)
	c.Set(CertCacheInstStorageKey, certCache)

	err := setupTLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if cfg.KeyType != acme.EC384 {
		t.Errorf("Expected 'P384' as KeyType, got %#v", cfg.KeyType)
	}
}

func TestSetupParseWithCurves(t *testing.T) {
	params := `tls {
            curves x25519 p256 p384 p521
        }`
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c := caddy.NewTestController("", params)
	c.Set(CertCacheInstStorageKey, certCache)

	err := setupTLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if len(cfg.CurvePreferences) != 4 {
		t.Errorf("Expected 4 curves, got %v", len(cfg.CurvePreferences))
	}

	expectedCurves := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}

	// Ensure ordering is correct
	for i, actual := range cfg.CurvePreferences {
		if actual != expectedCurves[i] {
			t.Errorf("Expected curve in position %d to be %v, got %v", i, expectedCurves[i], actual)
		}
	}
}

func TestSetupParseWithOneTLSProtocol(t *testing.T) {
	params := `tls {
            protocols tls1.2
        }`
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}
	RegisterConfigGetter("", func(c *caddy.Controller) *Config { return cfg })
	c := caddy.NewTestController("", params)
	c.Set(CertCacheInstStorageKey, certCache)

	err := setupTLS(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if cfg.ProtocolMinVersion != cfg.ProtocolMaxVersion {
		t.Errorf("Expected ProtocolMinVersion to be the same as ProtocolMaxVersion")
	}

	if cfg.ProtocolMinVersion != tls.VersionTLS12 && cfg.ProtocolMaxVersion != tls.VersionTLS12 {
		t.Errorf("Expected 'tls1.2 (0x0303)' as ProtocolMinVersion/ProtocolMaxVersion, got %v/%v", cfg.ProtocolMinVersion, cfg.ProtocolMaxVersion)
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
