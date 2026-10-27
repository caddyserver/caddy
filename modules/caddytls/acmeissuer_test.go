package caddytls

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/internal/network"
	"github.com/mholt/acmez/v3/acme"
)

func TestACMEIssuerExpandPlaceholders(t *testing.T) {
	t.Setenv("CADDY_TEST_CA_URL", "https://acme.example.com/directory")
	t.Setenv("CADDY_TEST_TEST_CA_URL", "https://acme2.example.com/directory")
	t.Setenv("CADDY_TEST_EAB_KEY_ID", "example-key-id")
	t.Setenv("CADDY_TEST_EAB_MAC_KEY", "example-mac-key")

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	iss := &ACMEIssuer{
		CA:     "{env.CADDY_TEST_CA_URL}",
		TestCA: "{env.CADDY_TEST_TEST_CA_URL}",
		ExternalAccount: &acme.EAB{
			KeyID:  "{env.CADDY_TEST_EAB_KEY_ID}",
			MACKey: "{env.CADDY_TEST_EAB_MAC_KEY}",
		},
	}

	if err := iss.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision() returned unexpected error: %v", err)
	}

	if want := "https://acme.example.com/directory"; iss.CA != want {
		t.Errorf("CA: got %q, want %q", iss.CA, want)
	}
	if want := "https://acme2.example.com/directory"; iss.TestCA != want {
		t.Errorf("TestCA: got %q, want %q", iss.TestCA, want)
	}
	if want := "example-key-id"; iss.ExternalAccount.KeyID != want {
		t.Errorf("ExternalAccount.KeyID: got %q, want %q", iss.ExternalAccount.KeyID, want)
	}
	if want := "example-mac-key"; iss.ExternalAccount.MACKey != want {
		t.Errorf("ExternalAccount.MACKey: got %q, want %q", iss.ExternalAccount.MACKey, want)
	}
}

// The HTTP app provisions ACME issuers a second time to fill in its ports;
// the configured network proxy must survive that (#8283).
func TestACMEIssuerNetworkProxySurvivesReprovision(t *testing.T) {
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	iss := &ACMEIssuer{
		NetworkProxyRaw: []byte(`{"from":"url","url":"http://proxy.example.com:8080"}`),
	}

	for i := 1; i <= 2; i++ {
		if err := iss.Provision(caddyCtx); err != nil {
			t.Fatalf("Provision() #%d returned unexpected error: %v", i, err)
		}
		if iss.template.HTTPProxy == nil {
			t.Fatalf("Provision() #%d: template has no HTTP proxy", i)
		}
		proxyURL, err := iss.template.HTTPProxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "acme.example.com"}})
		if err != nil {
			t.Fatalf("Provision() #%d: HTTP proxy returned unexpected error: %v", i, err)
		}
		if want := "http://proxy.example.com:8080"; proxyURL.String() != want {
			t.Errorf("Provision() #%d: proxy: got %q, want %q", i, proxyURL, want)
		}
	}
}
