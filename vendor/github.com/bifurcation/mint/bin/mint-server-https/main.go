package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/bifurcation/mint"
	"golang.org/x/net/http2"
)

var (
	port         string
	serverName   string
	certFile     string
	keyFile      string
	responseFile string
	h2           bool
	sendTickets  bool
	genCert      bool
)

type responder []byte

func (rsp responder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write(rsp)
}

// ParsePrivateKeyDER parses a PKCS #1, PKCS #8, or elliptic curve
// PEM-encoded private key.
// XXX: Inlined from github.com/cloudflare/cfssl because of build issues with that module
func ParsePrivateKeyPEM(keyPEM []byte) (key crypto.Signer, err error) {
	keyDER, _ := pem.Decode(keyPEM)
	if keyDER == nil {
		return nil, err
	}

	generalKey, err := x509.ParsePKCS8PrivateKey(keyDER.Bytes)
	if err != nil {
		generalKey, err = x509.ParsePKCS1PrivateKey(keyDER.Bytes)
		if err != nil {
			generalKey, err = x509.ParseECPrivateKey(keyDER.Bytes)
			if err != nil {
				// We don't include the actual error into
				// the final error. The reason might be
				// we don't want to leak any info about
				// the private key.
				return nil, fmt.Errorf("No successful private key decoder")
			}
		}
	}

	switch generalKey.(type) {
	case *rsa.PrivateKey:
		return generalKey.(*rsa.PrivateKey), nil
	case *ecdsa.PrivateKey:
		return generalKey.(*ecdsa.PrivateKey), nil
	}

	// should never reach here
	return nil, fmt.Errorf("Should be unreachable")
}

// ParseOneCertificateFromPEM attempts to parse one PEM encoded certificate object,
// either a raw x509 certificate or a PKCS #7 structure possibly containing
// multiple certificates, from the top of certsPEM, which itself may
// contain multiple PEM encoded certificate objects.
// XXX: Inlined from github.com/cloudflare/cfssl because of build issues with that module
func ParseOneCertificateFromPEM(certsPEM []byte) ([]*x509.Certificate, []byte, error) {
	block, rest := pem.Decode(certsPEM)
	if block == nil {
		return nil, rest, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	var certs = []*x509.Certificate{cert}
	return certs, rest, err
}

// ParseCertificatesPEM parses a sequence of PEM-encoded certificate and returns them,
// can handle PEM encoded PKCS #7 structures.
// XXX: Inlined from github.com/cloudflare/cfssl because of build issues with that module
func ParseCertificatesPEM(certsPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var err error
	certsPEM = bytes.TrimSpace(certsPEM)
	for len(certsPEM) > 0 {
		var cert []*x509.Certificate
		cert, certsPEM, err = ParseOneCertificateFromPEM(certsPEM)
		if err != nil {
			return nil, err
		} else if cert == nil {
			break
		}

		certs = append(certs, cert...)
	}
	if len(certsPEM) > 0 {
		return nil, fmt.Errorf("Trailing PEM data")
	}
	return certs, nil
}

func main() {
	flag.StringVar(&port, "port", "4430", "port")
	flag.StringVar(&serverName, "host", "example.com", "hostname")
	flag.StringVar(&certFile, "cert", "", "certificate chain in PEM or DER")
	flag.StringVar(&keyFile, "key", "", "private key in PEM format")
	flag.BoolVar(&genCert, "gencert", false, "generate a self-signed cert")
	flag.StringVar(&responseFile, "response", "", "file to serve")
	flag.BoolVar(&h2, "h2", false, "whether to use HTTP/2 (exclusively)")
	flag.BoolVar(&sendTickets, "tickets", true, "whether to send session tickets")
	flag.Parse()

	var certChain []*x509.Certificate
	var priv crypto.Signer
	var response []byte
	var err error

	if certFile != "" {
		if keyFile == "" {
			log.Fatalf("Can't specify -cert without -key")
		}
		if genCert {
			log.Fatalf("Can't specify -cert and -gencert together")
		}

		certs, err := ioutil.ReadFile(certFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		} else {
			certChain, err = ParseCertificatesPEM(certs)
			if err != nil {
				certChain, err = x509.ParseCertificates(certs)
				if err != nil {
					log.Fatalf("Error parsing certificates: %v", err)
				}
			}
		}

		keyPEM, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		} else {
			priv, err = ParsePrivateKeyPEM(keyPEM)
			if priv == nil || err != nil {
				log.Fatalf("Error parsing private key: %v", err)
			}
		}
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	} else if genCert {
		if keyFile != "" {
			log.Fatalf("Can't specify -gencert and -key together")
		}

		var cert *x509.Certificate
		priv, cert, err = mint.MakeNewSelfSignedCert(serverName, mint.RSA_PKCS1_SHA256)
		certChain = []*x509.Certificate{cert}
	} else {
		log.Fatalf("Must provide either -gencert or -key, -cert")
	}

	// Load response file
	if responseFile != "" {
		log.Printf("Loading response file: %v", responseFile)
		response, err = ioutil.ReadFile(responseFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	} else {
		response = []byte("Welcome to the TLS 1.3 zone!")
	}
	handler := responder(response)

	config := mint.Config{
		SendSessionTickets: true,
		ServerName:         serverName,
		NextProtos:         []string{"http/1.1"},
	}

	if h2 {
		config.NextProtos = []string{"h2"}
	}

	config.SendSessionTickets = sendTickets

	if certFile != "" && keyFile != "" {
		log.Printf("Loading cert: %v key: %v", certFile, keyFile)
	}
	config.Certificates = []*mint.Certificate{
		{
			Chain:      certChain,
			PrivateKey: priv,
		},
	}

	config.Init(false)

	service := "0.0.0.0:" + port
	srv := &http.Server{Handler: handler}

	log.Printf("Listening on port %v", port)
	// Need the inner loop here because the h1 server errors on a dropped connection
	// Need the outer loop here because the h2 server is per-connection
	for {
		listener, err := mint.Listen("tcp", service, &config)
		if err != nil {
			log.Printf("Listen Error: %v", err)
			continue
		}

		if !h2 {
			alert := srv.Serve(listener)
			if alert != mint.AlertNoAlert {
				log.Printf("Serve Error: %v", err)
			}
		} else {
			srv2 := new(http2.Server)
			opts := &http2.ServeConnOpts{
				Handler:    handler,
				BaseConfig: srv,
			}

			for {
				conn, err := listener.Accept()
				if err != nil {
					log.Printf("Accept error: %v", err)
					continue
				}
				go srv2.ServeConn(conn, opts)
			}
		}
	}
}
