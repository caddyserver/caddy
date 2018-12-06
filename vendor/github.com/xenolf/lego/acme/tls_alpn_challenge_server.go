package acme

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
)

const (
	// ACMETLS1Protocol is the ALPN Protocol ID for the ACME-TLS/1 Protocol.
	ACMETLS1Protocol = "acme-tls/1"

	// defaultTLSPort is the port that the TLSALPNProviderServer will default to
	// when no other port is provided.
	defaultTLSPort = "443"
)

// TLSALPNProviderServer implements ChallengeProvider for `TLS-ALPN-01`
// challenge. It may be instantiated without using the NewTLSALPNProviderServer
// if you want only to use the default values.
type TLSALPNProviderServer struct {
	iface    string
	port     string
	listener net.Listener
}

// NewTLSALPNProviderServer creates a new TLSALPNProviderServer on the selected
// interface and port. Setting iface and / or port to an empty string will make
// the server fall back to the "any" interface and port 443 respectively.
func NewTLSALPNProviderServer(iface, port string) *TLSALPNProviderServer {
	return &TLSALPNProviderServer{iface: iface, port: port}
}

// Present generates a certificate with a SHA-256 digest of the keyAuth provided
// as the acmeValidation-v1 extension value to conform to the ACME-TLS-ALPN
// spec.
func (t *TLSALPNProviderServer) Present(domain, token, keyAuth string) error {
	if t.port == "" {
		// Fallback to port 443 if the port was not provided.
		t.port = defaultTLSPort
	}

	// Generate the challenge certificate using the provided keyAuth and domain.
	cert, err := TLSALPNChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}

	// Place the generated certificate with the extension into the TLS config
	// so that it can serve the correct details.
	tlsConf := new(tls.Config)
	tlsConf.Certificates = []tls.Certificate{*cert}

	// We must set that the `acme-tls/1` application level protocol is supported
	// so that the protocol negotiation can succeed. Reference:
	// https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.2
	tlsConf.NextProtos = []string{ACMETLS1Protocol}

	// Create the listener with the created tls.Config.
	t.listener, err = tls.Listen("tcp", net.JoinHostPort(t.iface, t.port), tlsConf)
	if err != nil {
		return fmt.Errorf("could not start HTTPS server for challenge -> %v", err)
	}

	// Shut the server down when we're finished.
	go func() {
		http.Serve(t.listener, nil)
	}()

	return nil
}

// CleanUp closes the HTTPS server.
func (t *TLSALPNProviderServer) CleanUp(domain, token, keyAuth string) error {
	if t.listener == nil {
		return nil
	}

	// Server was created, close it.
	if err := t.listener.Close(); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}
