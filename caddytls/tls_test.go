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
	"os"
	"testing"

	"github.com/xenolf/lego/acme"
)

func TestHostQualifies(t *testing.T) {
	for i, test := range []struct {
		host   string
		expect bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"Sub.Example.COM", true},
		{"127.0.0.1", false},
		{"127.0.1.5", false},
		{"69.123.43.94", false},
		{"::1", false},
		{"::", false},
		{"0.0.0.0", false},
		{"", false},
		{" ", false},
		{"*.example.com", false},
		{".com", false},
		{"example.com.", false},
		{"localhost", false},
		{"local", true},
		{"devsite", true},
		{"192.168.1.3", false},
		{"10.0.2.1", false},
		{"169.112.53.4", false},
	} {
		actual := HostQualifies(test.host)
		if actual != test.expect {
			t.Errorf("Test %d: Expected HostQualifies(%s)=%v, but got %v",
				i, test.host, test.expect, actual)
		}
	}
}

type holder struct {
	host, port string
	cfg        *Config
}

func (h holder) TLSConfig() *Config { return h.cfg }
func (h holder) Host() string       { return h.host }
func (h holder) Port() string       { return h.port }

func TestQualifiesForManagedTLS(t *testing.T) {
	for i, test := range []struct {
		cfg    ConfigHolder
		expect bool
	}{
		{holder{host: ""}, false},
		{holder{host: "localhost"}, false},
		{holder{host: "123.44.3.21"}, false},
		{holder{host: "example.com"}, false},
		{holder{host: "", cfg: new(Config)}, false},
		{holder{host: "localhost", cfg: new(Config)}, false},
		{holder{host: "123.44.3.21", cfg: new(Config)}, false},
		{holder{host: "example.com", cfg: new(Config)}, true},
		{holder{host: "*.example.com", cfg: new(Config)}, false},
		{holder{host: "example.com", cfg: &Config{Manual: true}}, false},
		{holder{host: "example.com", cfg: &Config{ACMEEmail: "off"}}, false},
		{holder{host: "example.com", cfg: &Config{ACMEEmail: "foo@bar.com"}}, true},
		{holder{host: "example.com", port: "80"}, false},
		{holder{host: "example.com", port: "1234", cfg: new(Config)}, true},
		{holder{host: "example.com", port: "443", cfg: new(Config)}, true},
		{holder{host: "example.com", port: "80"}, false},
	} {
		if got, want := QualifiesForManagedTLS(test.cfg), test.expect; got != want {
			t.Errorf("Test %d: Expected %v but got %v", i, want, got)
		}
	}
}

func TestSaveCertResource(t *testing.T) {
	storage := &FileStorage{Path: "./le_test_save"}
	defer func() {
		err := os.RemoveAll(storage.Path)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", storage.Path, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"
	metaContents := `{
	"domain": "example.com",
	"certUrl": "https://example.com/cert",
	"certStableUrl": "https://example.com/cert/stable"
}`

	cert := acme.CertificateResource{
		Domain:        domain,
		CertURL:       "https://example.com/cert",
		CertStableURL: "https://example.com/cert/stable",
		PrivateKey:    []byte(keyContents),
		Certificate:   []byte(certContents),
	}

	err := saveCertResource(storage, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	siteData, err := storage.LoadSite(domain)
	if err != nil {
		t.Errorf("Expected no error reading site, got: %v", err)
	}
	if string(siteData.Cert) != certContents {
		t.Errorf("Expected certificate file to contain '%s', got '%s'", certContents, string(siteData.Cert))
	}
	if string(siteData.Key) != keyContents {
		t.Errorf("Expected private key file to contain '%s', got '%s'", keyContents, string(siteData.Key))
	}
	if string(siteData.Meta) != metaContents {
		t.Errorf("Expected meta file to contain '%s', got '%s'", metaContents, string(siteData.Meta))
	}
}

func TestExistingCertAndKey(t *testing.T) {
	storage := &FileStorage{Path: "./le_test_existing"}
	defer func() {
		err := os.RemoveAll(storage.Path)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", storage.Path, err)
		}
	}()

	domain := "example.com"

	siteExists, err := storage.SiteExists(domain)
	if err != nil {
		t.Fatalf("Could not determine whether site exists: %v", err)
	}

	if siteExists {
		t.Errorf("Did NOT expect %v to have existing cert or key, but it did", domain)
	}

	err = saveCertResource(storage, acme.CertificateResource{
		Domain:      domain,
		PrivateKey:  []byte("key"),
		Certificate: []byte("cert"),
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	siteExists, err = storage.SiteExists(domain)
	if err != nil {
		t.Fatalf("Could not determine whether site exists: %v", err)
	}

	if !siteExists {
		t.Errorf("Expected %v to have existing cert and key, but it did NOT", domain)
	}
}
