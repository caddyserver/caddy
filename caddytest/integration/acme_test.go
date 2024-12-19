package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	smallstepacme "github.com/smallstep/certificates/acme"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

const acmeChallengePort = 9081

// Test the basic functionality of Caddy's ACME server
func TestACMEServerWithDefaults(t *testing.T) {
	ctx := context.Background()
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

	certs, err := client.ObtainCertificateForSANs(ctx, account, certPrivateKey, []string{"localhost"})
	if err != nil {
		t.Errorf("obtaining certificate: %v", err)
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

func TestACMEServerWithMismatchedChallenges(t *testing.T) {
	ctx := context.Background()
	logger := caddy.Log().Named("acmez")

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
		acme_server {
			challenges tls-alpn-01
		}
	}
  `, "caddyfile")

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

	certs, err := client.ObtainCertificateForSANs(ctx, account, certPrivateKey, []string{"localhost"})
	if len(certs) > 0 {
		t.Errorf("expected '0' certificates, but received '%d'", len(certs))
	}
	if err == nil {
		t.Error("expected errors, but received none")
	}
	const expectedErrMsg = "no solvers available for remaining challenges (configured=[http-01] offered=[tls-alpn-01] remaining=[tls-alpn-01])"
	if !strings.Contains(err.Error(), expectedErrMsg) {
		t.Errorf(`received error message does not match expectation: expected="%s" received="%s"`, expectedErrMsg, err.Error())
	}
}

// naiveHTTPSolver is a no-op acmez.Solver for example purposes only.
type naiveHTTPSolver struct {
	srv    *http.Server
	logger *zap.Logger
}

func (s *naiveHTTPSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	smallstepacme.InsecurePortHTTP01 = acmeChallengePort
	s.srv = &http.Server{
		Addr: fmt.Sprintf(":%d", acmeChallengePort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}
			s.logger.Info("received request on challenge server", zap.String("path", r.URL.Path))
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
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", acmeChallengePort))
	if err != nil {
		return err
	}
	s.logger.Info("present challenge", zap.Any("challenge", challenge))
	go s.srv.Serve(l)
	return nil
}

func (s naiveHTTPSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	smallstepacme.InsecurePortHTTP01 = 0
	s.logger.Info("cleanup", zap.Any("challenge", challenge))
	if s.srv != nil {
		s.srv.Close()
	}
	return nil
}
