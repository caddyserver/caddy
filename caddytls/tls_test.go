package caddytls

import (
	"io/ioutil"
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
	storage := Storage("./le_test_save")
	defer func() {
		err := os.RemoveAll(string(storage))
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", storage, err)
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

	certFile, err := ioutil.ReadFile(storage.SiteCertFile(domain))
	if err != nil {
		t.Errorf("Expected no error reading certificate file, got: %v", err)
	}
	if string(certFile) != certContents {
		t.Errorf("Expected certificate file to contain '%s', got '%s'", certContents, string(certFile))
	}

	keyFile, err := ioutil.ReadFile(storage.SiteKeyFile(domain))
	if err != nil {
		t.Errorf("Expected no error reading private key file, got: %v", err)
	}
	if string(keyFile) != keyContents {
		t.Errorf("Expected private key file to contain '%s', got '%s'", keyContents, string(keyFile))
	}

	metaFile, err := ioutil.ReadFile(storage.SiteMetaFile(domain))
	if err != nil {
		t.Errorf("Expected no error reading meta file, got: %v", err)
	}
	if string(metaFile) != metaContents {
		t.Errorf("Expected meta file to contain '%s', got '%s'", metaContents, string(metaFile))
	}
}

func TestExistingCertAndKey(t *testing.T) {
	storage := Storage("./le_test_existing")
	defer func() {
		err := os.RemoveAll(string(storage))
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", storage, err)
		}
	}()

	domain := "example.com"

	if existingCertAndKey(storage, domain) {
		t.Errorf("Did NOT expect %v to have existing cert or key, but it did", domain)
	}

	err := saveCertResource(storage, acme.CertificateResource{
		Domain:      domain,
		PrivateKey:  []byte("key"),
		Certificate: []byte("cert"),
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !existingCertAndKey(storage, domain) {
		t.Errorf("Expected %v to have existing cert and key, but it did NOT", domain)
	}
}
