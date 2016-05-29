package caddytls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy2"
	"github.com/xenolf/lego/acme"
)

func init() {
	caddy.RegisterPlugin(caddy.Plugin{
		Name:   "tls",
		Action: Setup,
	})
}

// Setup sets up the TLS configuration and installs certificates that
// are specified by the user in the config file. All the automatic HTTPS
// stuff comes later outside of this function.
func Setup(c *caddy.Controller) error {
	// TODO: Do this in the server type, since we don't have that info here
	// if c.Port == "80" || c.Scheme == "http" {
	// 	config.Enabled = false
	// 	log.Printf("[WARNING] TLS disabled for %s://%s.", c.Scheme, c.Address())
	// 	return nil
	// }
	configGetter, ok := configGetters[c.ServerType]
	if !ok {
		return fmt.Errorf("no caddytls.ConfigGetter for %s server type; must call RegisterConfigGetter", c.ServerType)
	}
	config := configGetter(c.Key)
	if config == nil {
		return fmt.Errorf("no caddytls.Config to set up for %s", c.Key)
	}

	// TODO: What if hostname field of config is empty? That's kinda important

	config.Enabled = true

	for c.Next() {
		var certificateFile, keyFile, loadDir, maxCerts string

		args := c.RemainingArgs()
		switch len(args) {
		case 1:
			// user can force-disable managed TLS this way
			if args[0] == "off" {
				config.Enabled = false
				return nil
			}

			// user might want a temporary, in-memory, self-signed cert
			if args[0] == "self_signed" {
				config.SelfSigned = true
			}

			config.LetsEncryptEmail = args[0]
		case 2:
			certificateFile = args[0]
			keyFile = args[1]
			config.Manual = true
		}

		// Optional block with extra parameters
		var hadBlock bool
		for c.NextBlock() {
			hadBlock = true
			switch c.Val() {
			case "key_type":
				arg := c.RemainingArgs()
				value, ok := supportedKeyTypes[strings.ToUpper(arg[0])]
				if !ok {
					return c.Errf("Wrong key type name or key type not supported: '%s'", c.Val())
				}
				config.KeyType = value
			case "protocols":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return c.ArgErr()
				}
				value, ok := supportedProtocols[strings.ToLower(args[0])]
				if !ok {
					return c.Errf("Wrong protocol name or protocol not supported: '%s'", c.Val())
				}
				config.ProtocolMinVersion = value
				value, ok = supportedProtocols[strings.ToLower(args[1])]
				if !ok {
					return c.Errf("Wrong protocol name or protocol not supported: '%s'", c.Val())
				}
				config.ProtocolMaxVersion = value
			case "ciphers":
				for c.NextArg() {
					value, ok := supportedCiphersMap[strings.ToUpper(c.Val())]
					if !ok {
						return c.Errf("Wrong cipher name or cipher not supported: '%s'", c.Val())
					}
					config.Ciphers = append(config.Ciphers, value)
				}
			case "clients":
				clientCertList := c.RemainingArgs()
				if len(clientCertList) == 0 {
					return c.ArgErr()
				}

				listStart, mustProvideCA := 1, true
				switch clientCertList[0] {
				case "request":
					config.ClientAuth = tls.RequestClientCert
					mustProvideCA = false
				case "require":
					config.ClientAuth = tls.RequireAnyClientCert
					mustProvideCA = false
				case "verify_if_given":
					config.ClientAuth = tls.VerifyClientCertIfGiven
				default:
					config.ClientAuth = tls.RequireAndVerifyClientCert
					listStart = 0
				}
				if mustProvideCA && len(clientCertList) <= listStart {
					return c.ArgErr()
				}

				config.ClientCerts = clientCertList[listStart:]
			case "load":
				c.Args(&loadDir)
				config.Manual = true
			case "max_certs":
				c.Args(&maxCerts)
				config.OnDemand = true
			case "dns":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				switch args[0] {
				case "cloudflare", "digitalocean", "dnsimple",
					"dyn", "gandi", "gcloud", "namecheap",
					"rfc2136", "route53", "vultr":
					config.DNSProvider = args[0]
				default:
					return c.Errf("Unsupported DNS provider '%s'", args[0])
				}
			case "dev":

			default:
				return c.Errf("Unknown keyword '%s'", c.Val())
			}
		}

		// tls requires at least one argument if a block is not opened
		if len(args) == 0 && !hadBlock {
			return c.ArgErr()
		}

		// set certificate limit if on-demand TLS is enabled
		if maxCerts != "" {
			maxCertsNum, err := strconv.Atoi(maxCerts)
			if err != nil || maxCertsNum < 1 {
				return c.Err("max_certs must be a positive integer")
			}
			if onDemandMaxIssue == 0 || int32(maxCertsNum) < onDemandMaxIssue { // keep the minimum; TODO: We have to do this because it is global; should be per-server or per-vhost...
				onDemandMaxIssue = int32(maxCertsNum)
			}
		}

		// don't try to load certificates unless we're supposed to
		if !config.Enabled || !config.Manual {
			continue
		}

		// load a single certificate and key, if specified
		if certificateFile != "" && keyFile != "" {
			err := cacheUnmanagedCertificatePEMFile(certificateFile, keyFile)
			if err != nil {
				return c.Errf("Unable to load certificate and key files for '%s': %v", c.Key, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s and %s", certificateFile, keyFile)
		}

		// load a directory of certificates, if specified
		if loadDir != "" {
			err := loadCertsInDir(c, loadDir)
			if err != nil {
				return err
			}
		}
	}

	SetDefaultTLSParams(config)

	// generate self-signed cert if needed
	if config.SelfSigned {
		err := makeSelfSignedCert(config)
		if err != nil {
			return err
		}
	}

	return nil
}

func makeSelfSignedCert(config *Config) error {
	// start by generating private key
	var privKey interface{}
	var err error
	switch config.KeyType {
	case "", acme.EC256:
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case acme.EC384:
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case acme.RSA2048:
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case acme.RSA4096:
		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case acme.RSA8192:
		privKey, err = rsa.GenerateKey(rand.Reader, 8192)
	default:
		return fmt.Errorf("self-signed: cannot generate private key; unknown key type %v", config.KeyType)
	}
	if err != nil {
		return fmt.Errorf("self-signed: failed to generate private key: %v", err)
	}

	// create certificate structure with proper values
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour * 7)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("self-signed: failed to generate serial number: %v", err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Caddy Self-Signed"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(config.Hostname); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else {
		cert.DNSNames = append(cert.DNSNames, config.Hostname)
	}

	publicKey := func(privKey interface{}) interface{} {
		switch k := privKey.(type) {
		case *rsa.PrivateKey:
			return &k.PublicKey
		case *ecdsa.PrivateKey:
			return &k.PublicKey
		default:
			return nil
		}
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey(privKey), privKey)
	if err != nil {
		return fmt.Errorf("self-signed: could not create certificate: %v", err)
	}

	cacheCertificate(Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{derBytes},
			PrivateKey:  privKey,
			Leaf:        cert,
		},
		Names:    cert.DNSNames,
		NotAfter: cert.NotAfter,
		Config:   config,
	})

	return nil
}

// loadCertsInDir loads all the certificates/keys in dir, as long as
// the file ends with .pem. This method of loading certificates is
// modeled after haproxy, which expects the certificate and key to
// be bundled into the same file:
// https://cbonte.github.io/haproxy-dconv/configuration-1.5.html#5.1-crt
//
// This function may write to the log as it walks the directory tree.
func loadCertsInDir(c *caddy.Controller, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[WARNING] Unable to traverse into %s; skipping", path)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".pem") {
			certBuilder, keyBuilder := new(bytes.Buffer), new(bytes.Buffer)
			var foundKey bool // use only the first key in the file

			bundle, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			for {
				// Decode next block so we can see what type it is
				var derBlock *pem.Block
				derBlock, bundle = pem.Decode(bundle)
				if derBlock == nil {
					break
				}

				if derBlock.Type == "CERTIFICATE" {
					// Re-encode certificate as PEM, appending to certificate chain
					pem.Encode(certBuilder, derBlock)
				} else if derBlock.Type == "EC PARAMETERS" {
					// EC keys generated from openssl can be composed of two blocks:
					// parameters and key (parameter block should come first)
					if !foundKey {
						// Encode parameters
						pem.Encode(keyBuilder, derBlock)

						// Key must immediately follow
						derBlock, bundle = pem.Decode(bundle)
						if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
							return c.Errf("%s: expected elliptic private key to immediately follow EC parameters", path)
						}
						pem.Encode(keyBuilder, derBlock)
						foundKey = true
					}
				} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
					// RSA key
					if !foundKey {
						pem.Encode(keyBuilder, derBlock)
						foundKey = true
					}
				} else {
					return c.Errf("%s: unrecognized PEM block type: %s", path, derBlock.Type)
				}
			}

			certPEMBytes, keyPEMBytes := certBuilder.Bytes(), keyBuilder.Bytes()
			if len(certPEMBytes) == 0 {
				return c.Errf("%s: failed to parse PEM data", path)
			}
			if len(keyPEMBytes) == 0 {
				return c.Errf("%s: no private key block found", path)
			}

			err = cacheUnmanagedCertificatePEMBytes(certPEMBytes, keyPEMBytes)
			if err != nil {
				return c.Errf("%s: failed to load cert and key for '%s': %v", path, c.Key, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s", path)
		}
		return nil
	})
}
