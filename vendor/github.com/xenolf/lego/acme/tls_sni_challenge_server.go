package acme

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
)

// TLSProviderServer implements ChallengeProvider for `TLS-SNI-01` challenge
// It may be instantiated without using the NewTLSProviderServer function if
// you want only to use the default values.
type TLSProviderServer struct {
	iface    string
	port     string
	done     chan bool
	listener net.Listener
}

// NewTLSProviderServer creates a new TLSProviderServer on the selected interface and port.
// Setting iface and / or port to an empty string will make the server fall back to
// the "any" interface and port 443 respectively.
func NewTLSProviderServer(iface, port string) *TLSProviderServer {
	return &TLSProviderServer{iface: iface, port: port}
}

// Present makes the keyAuth available as a cert
func (s *TLSProviderServer) Present(domain, token, keyAuth string) error {
	if s.port == "" {
		s.port = "443"
	}

	cert, err := TLSSNI01ChallengeCert(keyAuth)
	if err != nil {
		return err
	}

	tlsConf := new(tls.Config)
	tlsConf.Certificates = []tls.Certificate{cert}

	s.listener, err = tls.Listen("tcp", net.JoinHostPort(s.iface, s.port), tlsConf)
	if err != nil {
		return fmt.Errorf("Could not start HTTPS server for challenge -> %v", err)
	}

	s.done = make(chan bool)
	go func() {
		http.Serve(s.listener, nil)
		s.done <- true
	}()
	return nil
}

// CleanUp closes the HTTP server.
func (s *TLSProviderServer) CleanUp(domain, token, keyAuth string) error {
	if s.listener == nil {
		return nil
	}
	s.listener.Close()
	<-s.done
	return nil
}
