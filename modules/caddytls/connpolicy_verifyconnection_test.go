package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"
)

type testClientCertificateVerifier struct {
	rawCerts       [][]byte
	verifiedChains [][]*x509.Certificate
	err            error
}

func (v *testClientCertificateVerifier) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
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

	err := clientauth.verifyConnection(tls.ConnectionState{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error %v, got %v", wantErr, err)
	}
}
