package tlsalpn01

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/xenolf/lego/log"
)

const (
	// ACMETLS1Protocol is the ALPN Protocol ID for the ACME-TLS/1 Protocol.
	ACMETLS1Protocol = "acme-tls/1"

	// defaultTLSPort is the port that the ProviderServer will default to
	// when no other port is provided.
	defaultTLSPort = "443"
)

// ProviderServer implements ChallengeProvider for `TLS-ALPN-01` challenge.
// It may be instantiated without using the NewProviderServer
// if you want only to use the default values.
type ProviderServer struct {
	iface    string
	port     string
	listener net.Listener
}

// NewProviderServer creates a new ProviderServer on the selected interface and port.
// Setting iface and / or port to an empty string will make the server fall back to
// the "any" interface and port 443 respectively.
func NewProviderServer(iface, port string) *ProviderServer {
	return &ProviderServer{iface: iface, port: port}
}

func (s *ProviderServer) GetAddress() string {
	return net.JoinHostPort(s.iface, s.port)
}

// Present generates a certificate with a SHA-256 digest of the keyAuth provided
// as the acmeValidation-v1 extension value to conform to the ACME-TLS-ALPN spec.
func (s *ProviderServer) Present(domain, token, keyAuth string) error {
	if s.port == "" {
		// Fallback to port 443 if the port was not provided.
		s.port = defaultTLSPort
	}

	// Generate the challenge certificate using the provided keyAuth and domain.
	cert, err := ChallengeCert(domain, keyAuth)
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
	s.listener, err = tls.Listen("tcp", s.GetAddress(), tlsConf)
	if err != nil {
		return fmt.Errorf("could not start HTTPS server for challenge -> %v", err)
	}

	// Shut the server down when we're finished.
	go func() {
		err := http.Serve(s.listener, nil)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Println(err)
		}
	}()

	return nil
}

// CleanUp closes the HTTPS server.
func (s *ProviderServer) CleanUp(domain, token, keyAuth string) error {
	if s.listener == nil {
		return nil
	}

	// Server was created, close it.
	if err := s.listener.Close(); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}
