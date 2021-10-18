package caddytls

import (
	"crypto/x509"
	"github.com/caddyserver/caddy/v2"
)

type RawClientCertValidations caddy.ModuleMap
type ClientCertValidator interface {
	VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}
