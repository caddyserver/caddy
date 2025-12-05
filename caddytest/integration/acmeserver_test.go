package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestACMEServerDirectory(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		local_certs
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		pki {
			ca local {
				name "Caddy Local Authority"
			}
		}
	}
	https://acme.localhost:{$TESTING_CADDY_PORT_TWO} {
		acme_server
	}
  `, "caddyfile")
	harness.AssertGetResponse(
		fmt.Sprintf("https://acme.localhost:%d/acme/local/directory", harness.Tester().PortTwo()),
		200,
		fmt.Sprintf(`{"newNonce":"https://acme.localhost:%[1]d/acme/local/new-nonce","newAccount":"https://acme.localhost:%[1]d/acme/local/new-account","newOrder":"https://acme.localhost:%[1]d/acme/local/new-order","revokeCert":"https://acme.localhost:%[1]d/acme/local/revoke-cert","keyChange":"https://acme.localhost:%[1]d/acme/local/key-change"}
`, harness.Tester().PortTwo()))
}

func TestACMEServerAllowPolicy(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		local_certs
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		pki {
			ca local {
				name "Caddy Local Authority"
			}
		}
	}
	acme.localhost {
		acme_server {
			challenges http-01
			allow {
				domains localhost
			}
		}
	}
  `, "caddyfile")

	ctx := context.Background()
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Error(err)
		return
	}

	client := acmez.Client{
		Client: &acme.Client{
			Directory:  fmt.Sprintf("https://acme.localhost:%d/acme/local/directory", harness.Tester().PortTwo()),
			HTTPClient: harness.Client(),
			Logger:     slog.New(zapslog.NewHandler(logger.Core())),
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeHTTP01: &naiveHTTPSolver{logger: logger},
		},
	}

	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("generating account key: %v", err)
	}
	account := acme.Account{
		Contact:              []string{"mailto:you@example.com"},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		t.Errorf("new account: %v", err)
		return
	}

	// Every certificate needs a key.
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("generating certificate key: %v", err)
		return
	}
	{
		certs, err := client.ObtainCertificateForSANs(ctx, account, certPrivateKey, []string{"localhost"})
		if err != nil {
			t.Errorf("obtaining certificate for allowed domain: %v", err)
			return
		}

		// ACME servers should usually give you the entire certificate chain
		// in PEM format, and sometimes even alternate chains! It's up to you
		// which one(s) to store and use, but whatever you do, be sure to
		// store the certificate and key somewhere safe and secure, i.e. don't
		// lose them!
		for _, cert := range certs {
			t.Logf("Certificate %q:\n%s\n\n", cert.URL, cert.ChainPEM)
		}
	}
	{
		_, err := client.ObtainCertificateForSANs(ctx, account, certPrivateKey, []string{"not-matching.localhost"})
		if err == nil {
			t.Errorf("obtaining certificate for 'not-matching.localhost' domain")
		} else if err != nil && !strings.Contains(err.Error(), "urn:ietf:params:acme:error:rejectedIdentifier") {
			t.Logf("unexpected error: %v", err)
		}
	}
}

func TestACMEServerDenyPolicy(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		local_certs
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		pki {
			ca local {
				name "Caddy Local Authority"
			}
		}
	}
	acme.localhost {
		acme_server {
			deny {
				domains deny.localhost
			}
		}
	}
  `, "caddyfile")

	ctx := context.Background()
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Error(err)
		return
	}

	client := acmez.Client{
		Client: &acme.Client{
			Directory:  fmt.Sprintf("https://acme.localhost:%d/acme/local/directory", harness.Tester().PortTwo()),
			HTTPClient: harness.Client(),
			Logger:     slog.New(zapslog.NewHandler(logger.Core())),
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeHTTP01: &naiveHTTPSolver{logger: logger},
		},
	}

	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("generating account key: %v", err)
	}
	account := acme.Account{
		Contact:              []string{"mailto:you@example.com"},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		t.Errorf("new account: %v", err)
		return
	}

	// Every certificate needs a key.
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("generating certificate key: %v", err)
		return
	}
	{
		_, err := client.ObtainCertificateForSANs(ctx, account, certPrivateKey, []string{"deny.localhost"})
		if err == nil {
			t.Errorf("obtaining certificate for 'deny.localhost' domain")
		} else if !strings.Contains(err.Error(), "urn:ietf:params:acme:error:rejectedIdentifier") {
			t.Logf("unexpected error: %v", err)
		}
	}
}
