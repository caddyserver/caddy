package https

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
		{server.Config{Host: ""}, false},
		{server.Config{Host: "localhost"}, false},
		{server.Config{Host: "123.44.3.21"}, false},
		{server.Config{Host: "example.com"}, true},
		{server.Config{Host: "example.com", TLS: server.TLSConfig{Manual: true}}, false},
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
	if actual, expected := handler.Rules[0].To, "https://{host}:1234{uri}"; actual != expected {
		t.Errorf("Expected redirect rule to be to URL '%s' but is actually to '%s'", expected, actual)
	}
	if actual, expected := handler.Rules[0].Code, http.StatusMovedPermanently; actual != expected {
		t.Errorf("Expected redirect rule to have code %d but was %d", expected, actual)
	}

	// browsers can infer a default port from scheme, so make sure the port
	// doesn't get added in explicitly for default ports like 443 for https.
	cfg = redirPlaintextHost(server.Config{Host: "example.com", Port: "443"})
	handler, ok = cfg.Middleware["/"][0](nil).(redirect.Redirect)
	if actual, expected := handler.Rules[0].To, "https://{host}{uri}"; actual != expected {
		t.Errorf("(Default Port) Expected redirect rule to be to URL '%s' but is actually to '%s'", expected, actual)
	}
}

func TestSaveCertResource(t *testing.T) {
	storage = Storage("./le_test_save")
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

func TestExistingCertAndKey(t *testing.T) {
	storage = Storage("./le_test_existing")
	defer func() {
		err := os.RemoveAll(string(storage))
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", storage, err)
		}
	}()

	domain := "example.com"

	if existingCertAndKey(domain) {
		t.Errorf("Did NOT expect %v to have existing cert or key, but it did", domain)
	}

	err := saveCertResource(acme.CertificateResource{
		Domain:      domain,
		PrivateKey:  []byte("key"),
		Certificate: []byte("cert"),
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !existingCertAndKey(domain) {
		t.Errorf("Expected %v to have existing cert and key, but it did NOT", domain)
	}
}

func TestHostHasOtherPort(t *testing.T) {
	configs := []server.Config{
		{Host: "example.com", Port: "80"},
		{Host: "sub1.example.com", Port: "80"},
		{Host: "sub1.example.com", Port: "443"},
	}

	if hostHasOtherPort(configs, 0, "80") {
		t.Errorf(`Expected hostHasOtherPort(configs, 0, "80") to be false, but got true`)
	}
	if hostHasOtherPort(configs, 0, "443") {
		t.Errorf(`Expected hostHasOtherPort(configs, 0, "443") to be false, but got true`)
	}
	if !hostHasOtherPort(configs, 1, "443") {
		t.Errorf(`Expected hostHasOtherPort(configs, 1, "443") to be true, but got false`)
	}
}

func TestMakePlaintextRedirects(t *testing.T) {
	configs := []server.Config{
		// Happy path = standard redirect from 80 to 443
		{Host: "example.com", TLS: server.TLSConfig{Managed: true}},

		// Host on port 80 already defined; don't change it (no redirect)
		{Host: "sub1.example.com", Port: "80", Scheme: "http"},
		{Host: "sub1.example.com", TLS: server.TLSConfig{Managed: true}},

		// Redirect from port 80 to port 5000 in this case
		{Host: "sub2.example.com", Port: "5000", TLS: server.TLSConfig{Managed: true}},

		// Can redirect from 80 to either 443 or 5001, but choose 443
		{Host: "sub3.example.com", Port: "443", TLS: server.TLSConfig{Managed: true}},
		{Host: "sub3.example.com", Port: "5001", Scheme: "https", TLS: server.TLSConfig{Managed: true}},
	}

	result := MakePlaintextRedirects(configs)
	expectedRedirCount := 3

	if len(result) != len(configs)+expectedRedirCount {
		t.Errorf("Expected %d redirect(s) to be added, but got %d",
			expectedRedirCount, len(result)-len(configs))
	}
}

func TestEnableTLS(t *testing.T) {
	configs := []server.Config{
		{Host: "example.com", TLS: server.TLSConfig{Managed: true}},
		{}, // not managed - no changes!
	}

	EnableTLS(configs, false)

	if !configs[0].TLS.Enabled {
		t.Errorf("Expected config 0 to have TLS.Enabled == true, but it was false")
	}
	if configs[1].TLS.Enabled {
		t.Errorf("Expected config 1 to have TLS.Enabled == false, but it was true")
	}
}

func TestGroupConfigsByEmail(t *testing.T) {
	if groupConfigsByEmail([]server.Config{}, false) == nil {
		t.Errorf("With empty input, returned map was nil, but expected non-nil map")
	}

	configs := []server.Config{
		{Host: "example.com", TLS: server.TLSConfig{LetsEncryptEmail: "", Managed: true}},
		{Host: "sub1.example.com", TLS: server.TLSConfig{LetsEncryptEmail: "foo@bar", Managed: true}},
		{Host: "sub2.example.com", TLS: server.TLSConfig{LetsEncryptEmail: "", Managed: true}},
		{Host: "sub3.example.com", TLS: server.TLSConfig{LetsEncryptEmail: "foo@bar", Managed: true}},
		{Host: "sub4.example.com", TLS: server.TLSConfig{LetsEncryptEmail: "", Managed: true}},
		{Host: "sub5.example.com", TLS: server.TLSConfig{LetsEncryptEmail: ""}}, // not managed
	}
	DefaultEmail = "test@example.com"

	groups := groupConfigsByEmail(configs, true)

	if groups == nil {
		t.Fatalf("Returned map was nil, but expected values")
	}

	if len(groups) != 2 {
		t.Errorf("Expected 2 groups, got %d: %#v", len(groups), groups)
	}
	if len(groups["foo@bar"]) != 2 {
		t.Errorf("Expected 2 configs for foo@bar, got %d: %#v", len(groups["foobar"]), groups["foobar"])
	}
	if len(groups[DefaultEmail]) != 3 {
		t.Errorf("Expected 3 configs for %s, got %d: %#v", DefaultEmail, len(groups["foobar"]), groups["foobar"])
	}
}

func TestMarkQualified(t *testing.T) {
	// TODO: TestConfigQualifies and this test share the same config list...
	configs := []server.Config{
		{Host: ""},
		{Host: "localhost"},
		{Host: "123.44.3.21"},
		{Host: "example.com"},
		{Host: "example.com", TLS: server.TLSConfig{Manual: true}},
		{Host: "example.com", TLS: server.TLSConfig{LetsEncryptEmail: "off"}},
		{Host: "example.com", TLS: server.TLSConfig{LetsEncryptEmail: "foo@bar.com"}},
		{Host: "example.com", Scheme: "http"},
		{Host: "example.com", Port: "80"},
		{Host: "example.com", Port: "1234"},
		{Host: "example.com", Scheme: "https"},
		{Host: "example.com", Port: "80", Scheme: "https"},
	}
	expectedManagedCount := 4

	MarkQualified(configs)

	count := 0
	for _, cfg := range configs {
		if cfg.TLS.Managed {
			count++
		}
	}

	if count != expectedManagedCount {
		t.Errorf("Expected %d managed configs, but got %d", expectedManagedCount, count)
	}
}
