//go:build !go1.27

package caddyhttp

import (
	"crypto/tls"
	"crypto/x509"
)

func getTLSServerCert(cs *tls.ConnectionState) *x509.Certificate {
	// tls.ConnectionState.LocalCertificate was introduced in Go 1.27.
	return nil
}
