// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"
)

// Mock net.Conn. Only job is to expose a local IP address.
type mockConn struct {
	Addr net.Addr
}

func (conn mockConn) Read(b []byte) (n int, err error) {
	return -1, errors.New("not implemented")
}

func (conn mockConn) Write(b []byte) (n int, err error) {
	return -1, errors.New("not implemented")
}

func (conn mockConn) Close() error {
	return errors.New("not implemented")
}

func (conn mockConn) LocalAddr() net.Addr {
	return conn.Addr
}

func (conn mockConn) RemoteAddr() net.Addr {
	return nil
}

func (conn mockConn) SetDeadline(t time.Time) error {
	return errors.New("not implemented")
}

func (conn mockConn) SetReadDeadline(t time.Time) error {
	return errors.New("not implemented")
}

func (conn mockConn) SetWriteDeadline(t time.Time) error {
	return errors.New("not implemented")
}

func TestGetCertificate(t *testing.T) {
	certCache := &certificateCache{cache: make(map[string]Certificate)}
	cfg := &Config{Certificates: make(map[string]string), certCache: certCache}

	var conn1 net.Conn = &mockConn{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 60001, Zone: ""}}
	var conn2 net.Conn = &mockConn{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: 60001, Zone: ""}}

	hello := &tls.ClientHelloInfo{Conn: conn1, ServerName: "example.com"}
	helloSub := &tls.ClientHelloInfo{Conn: conn1, ServerName: "sub.example.com"}
	helloNoSNI := &tls.ClientHelloInfo{Conn: conn1}
	helloNoSNIFallback := &tls.ClientHelloInfo{Conn: conn2}
	helloNoMatch := &tls.ClientHelloInfo{Conn: conn1, ServerName: "nomatch"} // TODO (see below)

	// When cache is empty
	if cert, err := cfg.GetCertificate(hello); err == nil {
		t.Errorf("GetCertificate should return error when cache is empty, got: %v", cert)
	}
	if cert, err := cfg.GetCertificate(helloNoSNI); err == nil {
		t.Errorf("GetCertificate should return error when cache is empty even if server name is blank, got: %v", cert)
	}

	// When cache has one certificate in it
	firstCert := Certificate{Names: []string{"example.com"}, Certificate: tls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"example.com"}}}}
	cfg.cacheCertificate(firstCert)
	if cert, err := cfg.GetCertificate(hello); err != nil {
		t.Errorf("Got an error but shouldn't have, when cert exists in cache: %v", err)
	} else if cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("Got wrong certificate with exact match; expected 'example.com', got: %v", cert)
	}
	if _, err := cfg.GetCertificate(helloNoSNI); err == nil {
		t.Error("Expected error with no SNI and single cert in cache")
	}

	// When retrieving wildcard certificate
	wildcardCert := Certificate{
		Names:       []string{"*.example.com"},
		Certificate: tls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"*.example.com"}}},
		Hash:        "(don't overwrite the first one)",
	}
	cfg.cacheCertificate(wildcardCert)
	if cert, err := cfg.GetCertificate(helloSub); err != nil {
		t.Errorf("Didn't get wildcard cert, got: cert=%v, err=%v ", cert, err)
	} else if cert.Leaf.DNSNames[0] != "*.example.com" {
		t.Errorf("Got wrong certificate, expected wildcard: %v", cert)
	}

	// When cache is NOT empty but there's no SNI
	if _, err := cfg.GetCertificate(helloNoSNI); err == nil {
		t.Error("Expected error with no SNI multiple certs in cache")
	}

	// When no certificate matches, raise an alert
	if _, err := cfg.GetCertificate(helloNoMatch); err == nil {
		t.Error("Expected an error when no certificate matched the SNI")
	}

	// When no SNI, find a certificate with a matching IP address
	ipCert := Certificate{
		Names:       []string{"127.0.0.1"},
		Certificate: tls.Certificate{Leaf: &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}},
		Hash:        "127.0.0.1",
	}
	cfg.cacheCertificate(ipCert)
	if cert, err := cfg.GetCertificate(helloNoSNI); err != nil {
		t.Errorf("Got an error but shouldn't have, when no SNI and cert for IP address exists in cache: %v", err)
	} else if cert == nil || len(cert.Leaf.IPAddresses) == 0 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("Got wrong cert when no SNI and cert for IP address exists in cache: %v", err)
	}

	// Raise an alert when no SNI and no matching IP address.
	if _, err := cfg.GetCertificate(helloNoSNIFallback); err == nil {
		t.Error("Expected an error when no certificate matched the IP address with no SNI")
	}
}
