package caddytls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

type testClientCertificateVerifier struct {
	called         bool
	rawCerts       [][]byte
	verifiedChains [][]*x509.Certificate
	err            error
}

func (v *testClientCertificateVerifier) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	v.called = true
	v.rawCerts = rawCerts
	v.verifiedChains = verifiedChains
	return v.err
}

func TestClientAuthenticationVerifyConnectionPassesRawCertsToVerifiers(t *testing.T) {
	verifier := &testClientCertificateVerifier{}
	clientauth := &ClientAuthentication{
		verifiers: []ClientCertificateVerifier{verifier},
	}

	peerCert := &x509.Certificate{Raw: []byte("peer-cert-raw")}
	verifiedChains := [][]*x509.Certificate{{peerCert}}
	connState := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peerCert},
		VerifiedChains:   verifiedChains,
	}

	if err := clientauth.verifyConnection(connState); err != nil {
		t.Fatalf("verifyConnection failed: %v", err)
	}

	if !reflect.DeepEqual(verifier.rawCerts, [][]byte{[]byte("peer-cert-raw")}) {
		t.Fatalf("unexpected raw certs: got %#v", verifier.rawCerts)
	}
	if !reflect.DeepEqual(verifier.verifiedChains, verifiedChains) {
		t.Fatalf("unexpected verified chains: got %#v", verifier.verifiedChains)
	}
}

func TestClientAuthenticationVerifyConnectionReturnsVerifierError(t *testing.T) {
	wantErr := errors.New("verify failed")
	verifier := &testClientCertificateVerifier{err: wantErr}
	clientauth := &ClientAuthentication{
		verifiers: []ClientCertificateVerifier{verifier},
	}

	peerCert := &x509.Certificate{Raw: []byte("peer-cert-raw")}
	err := clientauth.verifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peerCert},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error %v, got %v", wantErr, err)
	}
}

func TestClientAuthenticationVerifyConnectionSkipsVerifiersWithoutPeerCert(t *testing.T) {
	verifier := &testClientCertificateVerifier{err: errors.New("verify failed")}
	clientauth := &ClientAuthentication{
		verifiers: []ClientCertificateVerifier{verifier},
	}

	if err := clientauth.verifyConnection(tls.ConnectionState{}); err != nil {
		t.Fatalf("verifyConnection failed: %v", err)
	}
	if verifier.called {
		t.Fatal("verifier was called without a peer certificate")
	}
}

func TestClientAuthenticationModeWithLeafVerifier(t *testing.T) {
	ca := issueTestCert(t, nil, 0)
	serverCert := issueTestCert(t, &ca, x509.ExtKeyUsageServerAuth)
	trusted := issueTestCert(t, &ca, x509.ExtKeyUsageClientAuth)
	untrusted := issueTestCert(t, &ca, x509.ExtKeyUsageClientAuth)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Leaf)

	for _, tc := range []struct {
		mode      string
		cert      *tls.Certificate
		wantError bool
	}{
		{mode: "request", cert: nil, wantError: false},
		{mode: "request", cert: &trusted, wantError: false},
		{mode: "request", cert: &untrusted, wantError: true},
		{mode: "require", cert: nil, wantError: true},
		{mode: "require", cert: &trusted, wantError: false},
		{mode: "require", cert: &untrusted, wantError: true},
		{mode: "verify_if_given", cert: nil, wantError: false},
		{mode: "verify_if_given", cert: &trusted, wantError: false},
		{mode: "verify_if_given", cert: &untrusted, wantError: true},
		{mode: "require_and_verify", cert: nil, wantError: true},
		{mode: "require_and_verify", cert: &trusted, wantError: false},
		{mode: "require_and_verify", cert: &untrusted, wantError: true},
	} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			clientauth := &ClientAuthentication{
				Mode:      tc.mode,
				ca:        InlineCAPool{pool: caPool},
				verifiers: []ClientCertificateVerifier{LeafCertClientAuth{trustedLeafCerts: []*x509.Certificate{trusted.Leaf}}},
			}
			serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
			if err := clientauth.ConfigureTLSConfig(serverConfig); err != nil {
				t.Fatalf("configuring TLS: %v", err)
			}
			clientConfig := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         version,
				MaxVersion:         version,
			}
			if tc.cert != nil {
				clientConfig.Certificates = []tls.Certificate{*tc.cert}
			}

			err := serverHandshake(t, serverConfig, clientConfig)
			certName := "no certificate"
			if tc.cert != nil {
				certName = tc.cert.Leaf.Subject.CommonName
			}
			if tc.wantError && err == nil {
				t.Errorf("mode %s, %s, %s: expected handshake error but got none", tc.mode, tls.VersionName(version), certName)
			}
			if !tc.wantError && err != nil {
				t.Errorf("mode %s, %s, %s: unexpected handshake error: %v", tc.mode, tls.VersionName(version), certName, err)
			}
		}
	}
}

func TestClientAuthenticationVerifyModesNeedTrustPool(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	// verifiers are loaded by the connection policy, so set both fields like a provisioned config
	verifiersRaw := []json.RawMessage{json.RawMessage(`{"verifier":"leaf"}`)}
	verifiers := []ClientCertificateVerifier{LeafCertClientAuth{trustedLeafCerts: []*x509.Certificate{issueTestCert(t, nil, 0).Leaf}}}
	customPool := json.RawMessage(`{"provider":"inline","trusted_ca_certs":["` + test_der_1 + `"]}`)
	systemPool := json.RawMessage(`{"provider":"system"}`)

	for i, tc := range []struct {
		clientauth ClientAuthentication
		want       tls.ClientAuthType
		wantErr    bool
	}{
		{clientauth: ClientAuthentication{Mode: "verify_if_given"}, wantErr: true},
		{clientauth: ClientAuthentication{Mode: "require_and_verify"}, wantErr: true},
		{clientauth: ClientAuthentication{Mode: "require_and_verify", VerifiersRaw: verifiersRaw, verifiers: verifiers}, wantErr: true},
		{clientauth: ClientAuthentication{Mode: "verify_if_given", CARaw: systemPool}, want: tls.VerifyClientCertIfGiven},
		{clientauth: ClientAuthentication{Mode: "require_and_verify", CARaw: systemPool}, want: tls.RequireAndVerifyClientCert},
		{clientauth: ClientAuthentication{Mode: "verify_if_given", CARaw: customPool}, want: tls.VerifyClientCertIfGiven},
		{clientauth: ClientAuthentication{Mode: "require_and_verify", CARaw: customPool}, want: tls.RequireAndVerifyClientCert},
		{clientauth: ClientAuthentication{CARaw: customPool}, want: tls.RequireAndVerifyClientCert},
		{clientauth: ClientAuthentication{Mode: "request"}, want: tls.RequestClientCert},
		{clientauth: ClientAuthentication{Mode: "require"}, want: tls.RequireAnyClientCert},
		{clientauth: ClientAuthentication{VerifiersRaw: verifiersRaw, verifiers: verifiers}, want: tls.RequireAnyClientCert},
		{clientauth: ClientAuthentication{TrustedLeafCerts: []string{test_der_1}}, want: tls.RequireAnyClientCert},
	} {
		if err := tc.clientauth.provision(ctx); err != nil {
			t.Fatalf("Test %d: provisioning: %v", i, err)
		}
		cfg := new(tls.Config)
		err := tc.clientauth.ConfigureTLSConfig(cfg)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d: expected error but got none", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if cfg.ClientAuth != tc.want {
			t.Errorf("Test %d: expected %v, got %v", i, tc.want, cfg.ClientAuth)
		}
		if tc.clientauth.CARaw != nil && cfg.ClientCAs == nil {
			t.Errorf("Test %d: expected ClientCAs to be set", i)
		}
	}
}

func TestClientAuthenticationVerifierOnlyHandshake(t *testing.T) {
	ca := issueTestCert(t, nil, 0)
	serverCert := issueTestCert(t, &ca, x509.ExtKeyUsageServerAuth)
	trusted := issueTestCert(t, &ca, x509.ExtKeyUsageClientAuth)
	untrusted := issueTestCert(t, &ca, x509.ExtKeyUsageClientAuth)

	for _, tc := range []struct {
		cert      *tls.Certificate
		wantError bool
	}{
		{cert: nil, wantError: true},
		{cert: &trusted, wantError: false},
		{cert: &untrusted, wantError: true},
	} {
		// no mode and no trust pool, so only the verifier checks the cert
		clientauth := &ClientAuthentication{
			VerifiersRaw: []json.RawMessage{json.RawMessage(`{"verifier":"leaf"}`)},
			verifiers:    []ClientCertificateVerifier{LeafCertClientAuth{trustedLeafCerts: []*x509.Certificate{trusted.Leaf}}},
		}
		serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
		if err := clientauth.ConfigureTLSConfig(serverConfig); err != nil {
			t.Fatalf("configuring TLS: %v", err)
		}
		clientConfig := &tls.Config{InsecureSkipVerify: true}
		if tc.cert != nil {
			clientConfig.Certificates = []tls.Certificate{*tc.cert}
		}

		err := serverHandshake(t, serverConfig, clientConfig)
		if tc.wantError && err == nil {
			t.Errorf("cert %v: expected handshake error but got none", tc.cert != nil)
		}
		if !tc.wantError && err != nil {
			t.Errorf("cert %v: unexpected handshake error: %v", tc.cert != nil, err)
		}
	}
}

// serverHandshake runs one TLS handshake over loopback TCP and returns
// the server's handshake error.
func serverHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tlsConn := tls.Server(conn, serverConfig)
		errCh <- tlsConn.Handshake()
		tlsConn.Close()
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	if err == nil {
		// wait for the server to finish before closing
		_, _ = conn.Read(make([]byte, 1))
		conn.Close()
	}
	return <-errCh
}

// issueTestCert returns a certificate signed by parent, or a self-signed
// CA certificate if parent is nil.
func issueTestCert(t *testing.T, parent *tls.Certificate, extKeyUsage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test " + serial.String()},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signer, signerKey := template, crypto.Signer(key)
	if parent == nil {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{extKeyUsage}
		signer, signerKey = parent.Leaf, parent.PrivateKey.(crypto.Signer)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
