package quic

import (
	gocrypto "crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

func tlsToMintConfig(tlsConf *tls.Config, pers protocol.Perspective) (*mint.Config, error) {
	mconf := &mint.Config{
		NonBlocking: true,
		CipherSuites: []mint.CipherSuite{
			mint.TLS_AES_128_GCM_SHA256,
			mint.TLS_AES_256_GCM_SHA384,
		},
	}
	if tlsConf != nil {
		mconf.ServerName = tlsConf.ServerName
		mconf.InsecureSkipVerify = tlsConf.InsecureSkipVerify
		mconf.Certificates = make([]*mint.Certificate, len(tlsConf.Certificates))
		mconf.RootCAs = tlsConf.RootCAs
		mconf.VerifyPeerCertificate = tlsConf.VerifyPeerCertificate
		for i, certChain := range tlsConf.Certificates {
			mconf.Certificates[i] = &mint.Certificate{
				Chain:      make([]*x509.Certificate, len(certChain.Certificate)),
				PrivateKey: certChain.PrivateKey.(gocrypto.Signer),
			}
			for j, cert := range certChain.Certificate {
				c, err := x509.ParseCertificate(cert)
				if err != nil {
					return nil, err
				}
				mconf.Certificates[i].Chain[j] = c
			}
		}
		switch tlsConf.ClientAuth {
		case tls.NoClientCert:
		case tls.RequireAnyClientCert:
			mconf.RequireClientAuth = true
		default:
			return nil, errors.New("mint currently only support ClientAuthType RequireAnyClientCert")
		}
	}
	if err := mconf.Init(pers == protocol.PerspectiveClient); err != nil {
		return nil, err
	}
	return mconf, nil
}
