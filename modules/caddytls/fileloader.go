package caddytls

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"

	"github.com/caddyserver/caddy"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "tls.certificates.load_files",
		New:  func() interface{} { return fileLoader{} },
	})
}

// fileLoader loads certificates and their associated keys from disk.
type fileLoader []CertKeyFilePair

// CertKeyFilePair pairs certificate and key file names along with their
// encoding format so that they can be loaded from disk.
type CertKeyFilePair struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	Format      string `json:"format,omitempty"` // "pem" is default
}

// LoadCertificates returns the certificates to be loaded by fl.
func (fl fileLoader) LoadCertificates() ([]tls.Certificate, error) {
	var certs []tls.Certificate
	for _, pair := range fl {
		certData, err := ioutil.ReadFile(pair.Certificate)
		if err != nil {
			return nil, err
		}
		keyData, err := ioutil.ReadFile(pair.Key)
		if err != nil {
			return nil, err
		}

		var cert tls.Certificate
		switch pair.Format {
		case "":
			fallthrough
		case "pem":
			cert, err = tls.X509KeyPair(certData, keyData)
		default:
			return nil, fmt.Errorf("unrecognized certificate/key encoding format: %s", pair.Format)
		}
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}
	return certs, nil
}

// Interface guard
var _ CertificateLoader = (fileLoader)(nil)
