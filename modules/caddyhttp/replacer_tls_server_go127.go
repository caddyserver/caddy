//go:build go1.27

package caddyhttp

import (
	"crypto/tls"
	"crypto/x509"
)

func getTLSServerCert(cs *tls.ConnectionState) *x509.Certificate {
	if len(cs.LocalCertificate) == 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(cs.LocalCertificate[0])
	if err != nil {
		return nil
	}
	return cert
}
