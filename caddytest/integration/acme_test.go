package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

// Test the basic functionality of Caddy's ACME server
func TestACMEServerWithDefaults(t *testing.T) {
	ctx := context.Background()
	// Logging is important - replace with your own zap logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Error(err)
		return
	}

	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		local_certs
	}
	acme.localhost {
		acme_server
	}
  `, "caddyfile")

	datadir := caddy.AppDataDir()
	rootCertsGlob := filepath.Join(datadir, "pki", "authorities", "local", "*.crt")
	matches, err := filepath.Glob(rootCertsGlob)
	if err != nil {
		t.Errorf("could not find root certs: %s", err)
		return
	}
	certPool := x509.NewCertPool()
	for _, m := range matches {
		certPem, err := os.ReadFile(m)
		if err != nil {
			t.Errorf("reading cert file '%s' error: %s", m, err)
			return
		}
		if !certPool.AppendCertsFromPEM(certPem) {
			t.Errorf("failed to append the cert: %s", m)
			return
		}
	}

	client := acmez.Client{
		Client: &acme.Client{
			Directory: "https://acme.localhost:9443/acme/local/directory",
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: certPool,
					},
				},
			},
			Logger: logger,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeHTTP01: naiveHTTPSolver{logger: logger},
		},
	}

	// Before you can get a cert, you'll need an account registered with
	// the ACME CA; it needs a private key which should obviously be
	// different from any key used for certificates!
	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("generating account key: %v", err)
	}
	account := acme.Account{
		Contact:              []string{"mailto:you@example.com"},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}

	// If the account is new, we need to create it; only do this once!
	// then be sure to securely store the account key and metadata so
	// you can reuse it later!
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		t.Errorf("new account: %v", err)
	}

	// Every certificate needs a key.
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("generating certificate key: %v", err)
	}

	certs, err := client.ObtainCertificate(ctx, account, certPrivateKey, []string{"acme-client.localhost"})
	if err != nil {
		t.Errorf("obtaining certificate: %v", err)
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

// naiveHTTPSolver is a no-op acmez.Solver for example purposes only.
type naiveHTTPSolver struct {
	srv    *http.Server
	logger *zap.Logger
}

func (s naiveHTTPSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	s.srv = &http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}
			if r.Method == "GET" && r.URL.Path == challenge.HTTP01ResourcePath() && strings.EqualFold(host, challenge.Identifier.Value) {

				w.Header().Add("Content-Type", "text/plain")
				w.Write([]byte(challenge.KeyAuthorization))
				r.Close = true
				s.logger.Info("served key authentication",
					zap.String("identifier", challenge.Identifier.Value),
					zap.String("challenge", "http-01"),
					zap.String("remote", r.RemoteAddr),
				)
			}
		}),
	}
	l, err := net.Listen("tcp", ":80")
	if err != nil {
		return err
	}
	s.logger.Info("present challenge", zap.Any("challenge", challenge))
	go s.srv.Serve(l)
	return nil
}

func (s naiveHTTPSolver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] cleanup: %#v", chal)
	if s.srv != nil {
		s.srv.Close()
	}
	return nil
}
