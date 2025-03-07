package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

func TestACMEServerDirectory(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		local_certs
		admin localhost:2999
		http_port     9080
		https_port    9443
		pki {
			ca local {
				name "Caddy Local Authority"
			}
		}
	}
	acme.localhost:9443 {
		acme_server
	}
  `, "caddyfile")
	tester.AssertGetResponse(
		"https://acme.localhost:9443/acme/local/directory",
		200,
		`{"newNonce":"https://acme.localhost:9443/acme/local/new-nonce","newAccount":"https://acme.localhost:9443/acme/local/new-account","newOrder":"https://acme.localhost:9443/acme/local/new-order","revokeCert":"https://acme.localhost:9443/acme/local/revoke-cert","keyChange":"https://acme.localhost:9443/acme/local/key-change"}
`)
}

func TestACMEServerAllowPolicy(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		local_certs
		admin localhost:2999
		http_port     9080
		https_port    9443
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
			Directory:  "https://acme.localhost:9443/acme/local/directory",
			HTTPClient: tester.Client,
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
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		local_certs
		admin localhost:2999
		http_port     9080
		https_port    9443
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
			Directory:  "https://acme.localhost:9443/acme/local/directory",
			HTTPClient: tester.Client,
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
		} else if err != nil && !strings.Contains(err.Error(), "urn:ietf:params:acme:error:rejectedIdentifier") {
			t.Logf("unexpected error: %v", err)
		}
	}
}
