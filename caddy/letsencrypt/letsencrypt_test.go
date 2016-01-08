package letsencrypt

import (
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

func TestHostQualifies(t *testing.T) {
	for i, test := range []struct {
		host   string
		expect bool
	}{
		{"localhost", false},
		{"127.0.0.1", false},
		{"127.0.1.5", false},
		{"::1", false},
		{"[::1]", false},
		{"[::]", false},
		{"::", false},
		{"", false},
		{" ", false},
		{"0.0.0.0", false},
		{"192.168.1.3", false},
		{"10.0.2.1", false},
		{"169.112.53.4", false},
		{"foobar.com", true},
		{"sub.foobar.com", true},
	} {
		if HostQualifies(test.host) && !test.expect {
			t.Errorf("Test %d: Expected '%s' to NOT qualify, but it did", i, test.host)
		}
		if !HostQualifies(test.host) && test.expect {
			t.Errorf("Test %d: Expected '%s' to qualify, but it did NOT", i, test.host)
		}
	}
}

func TestConfigQualifies(t *testing.T) {
	for i, test := range []struct {
		cfg    server.Config
		expect bool
	}{
		{server.Config{Host: "localhost"}, false},
		{server.Config{Host: "example.com"}, true},
		{server.Config{Host: "example.com", TLS: server.TLSConfig{Certificate: "cert.pem"}}, false},
		{server.Config{Host: "example.com", TLS: server.TLSConfig{Key: "key.pem"}}, false},
		{server.Config{Host: "example.com", TLS: server.TLSConfig{LetsEncryptEmail: "off"}}, false},
		{server.Config{Host: "example.com", TLS: server.TLSConfig{LetsEncryptEmail: "foo@bar.com"}}, true},
		{server.Config{Host: "example.com", Scheme: "http"}, false},
		{server.Config{Host: "example.com", Port: "80"}, false},
		{server.Config{Host: "example.com", Port: "1234"}, true},
		{server.Config{Host: "example.com", Scheme: "https"}, true},
		{server.Config{Host: "example.com", Port: "80", Scheme: "https"}, false},
	} {
		if test.expect && !ConfigQualifies(test.cfg) {
			t.Errorf("Test %d: Expected config to qualify, but it did NOT: %#v", i, test.cfg)
		}
		if !test.expect && ConfigQualifies(test.cfg) {
			t.Errorf("Test %d: Expected config to NOT qualify, but it did: %#v", i, test.cfg)
		}
	}
}

func TestRedirPlaintextHost(t *testing.T) {
	cfg := redirPlaintextHost(server.Config{
		Host:     "example.com",
		BindHost: "93.184.216.34",
		Port:     "1234",
	})

	// Check host and port
	if actual, expected := cfg.Host, "example.com"; actual != expected {
		t.Errorf("Expected redir config to have host %s but got %s", expected, actual)
	}
	if actual, expected := cfg.BindHost, "93.184.216.34"; actual != expected {
		t.Errorf("Expected redir config to have bindhost %s but got %s", expected, actual)
	}
	if actual, expected := cfg.Port, "80"; actual != expected {
		t.Errorf("Expected redir config to have port '%s' but got '%s'", expected, actual)
	}

	// Make sure redirect handler is set up properly
	if cfg.Middleware == nil || len(cfg.Middleware["/"]) != 1 {
		t.Fatalf("Redir config middleware not set up properly; got: %#v", cfg.Middleware)
	}

	handler, ok := cfg.Middleware["/"][0](nil).(redirect.Redirect)
	if !ok {
		t.Fatalf("Expected a redirect.Redirect middleware, but got: %#v", handler)
	}
	if len(handler.Rules) != 1 {
		t.Fatalf("Expected one redirect rule, got: %#v", handler.Rules)
	}

	// Check redirect rule for correctness
	if actual, expected := handler.Rules[0].FromScheme, "http"; actual != expected {
		t.Errorf("Expected redirect rule to be from scheme '%s' but is actually from '%s'", expected, actual)
	}
	if actual, expected := handler.Rules[0].FromPath, "/"; actual != expected {
		t.Errorf("Expected redirect rule to be for path '%s' but is actually for '%s'", expected, actual)
	}
	if actual, expected := handler.Rules[0].To, "https://example.com:1234{uri}"; actual != expected {
		t.Errorf("Expected redirect rule to be to URL '%s' but is actually to '%s'", expected, actual)
	}
	if actual, expected := handler.Rules[0].Code, http.StatusMovedPermanently; actual != expected {
		t.Errorf("Expected redirect rule to have code %d but was %d", expected, actual)
	}

	// browsers can interpret default ports with scheme, so make sure the port
	// doesn't get added in explicitly for default ports.
	cfg = redirPlaintextHost(server.Config{Host: "example.com", Port: "443"})
	handler, ok = cfg.Middleware["/"][0](nil).(redirect.Redirect)
	if actual, expected := handler.Rules[0].To, "https://example.com{uri}"; actual != expected {
		t.Errorf("(Default Port) Expected redirect rule to be to URL '%s' but is actually to '%s'", expected, actual)
	}
}

func TestSaveCertResource(t *testing.T) {
	storage = Storage("./le_test")
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

	err := saveCertResource(cert)
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
