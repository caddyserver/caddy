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

// ConfigGetter gets a Config keyed by key.
type ConfigGetter func(key string) *Config

var configGetters = make(map[string]ConfigGetter)

func RegisterConfigGetter(serverType string, fn ConfigGetter) {
	configGetters[serverType] = fn
}

// setup sets up the TLS configuration and installs certificates that
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

// SetDefaultTLSParams sets the default TLS cipher suites, protocol versions,
// and server preferences of a server.Config if they were not previously set
// (it does not overwrite; only fills in missing values).
func SetDefaultTLSParams(config *Config) {
	// If no ciphers provided, use default list
	if len(config.Ciphers) == 0 {
		config.Ciphers = defaultCiphers
	}

	// Not a cipher suite, but still important for mitigating protocol downgrade attacks
	// (prepend since having it at end breaks http2 due to non-h2-approved suites before it)
	config.Ciphers = append([]uint16{tls.TLS_FALLBACK_SCSV}, config.Ciphers...)

	// Set default protocol min and max versions - must balance compatibility and security
	if config.ProtocolMinVersion == 0 {
		config.ProtocolMinVersion = tls.VersionTLS11
	}
	if config.ProtocolMaxVersion == 0 {
		config.ProtocolMaxVersion = tls.VersionTLS12
	}

	// Prefer server cipher suites
	config.PreferServerCipherSuites = true
}

// Map of supported key types
var supportedKeyTypes = map[string]acme.KeyType{
	"P384":    acme.EC384,
	"P256":    acme.EC256,
	"RSA8192": acme.RSA8192,
	"RSA4096": acme.RSA4096,
	"RSA2048": acme.RSA2048,
}

// Map of supported protocols.
// HTTP/2 only supports TLS 1.2 and higher.
var supportedProtocols = map[string]uint16{
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
	"tls1.2": tls.VersionTLS12,
}

// Map of supported ciphers, used only for parsing config.
//
// Note that, at time of writing, HTTP/2 blacklists 276 cipher suites,
// including all but two of the suites below (the two GCM suites).
// See https://http2.github.io/http2-spec/#BadCipherSuites
//
// TLS_FALLBACK_SCSV is not in this list because we manually ensure
// it is always added (even though it is not technically a cipher suite).
//
// This map, like any map, is NOT ORDERED. Do not range over this map.
var supportedCiphersMap = map[string]uint16{
	"ECDHE-RSA-AES256-GCM-SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-AES256-GCM-SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES128-GCM-SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES128-GCM-SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES128-CBC-SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-RSA-AES256-CBC-SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE-ECDSA-AES256-CBC-SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE-ECDSA-AES128-CBC-SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"RSA-AES128-CBC-SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"RSA-AES256-CBC-SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE-RSA-3DES-EDE-CBC-SHA":    tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"RSA-3DES-EDE-CBC-SHA":          tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// List of supported cipher suites in descending order of preference.
// Ordering is very important! Getting the wrong order will break
// mainstream clients, especially with HTTP/2.
//
// Note that TLS_FALLBACK_SCSV is not in this list since it is always
// added manually.
var supportedCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// List of all the ciphers we want to use by default
var defaultCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
}

// Config describes how TLS should be configured and used.
// TODO: Some of these should be scoped per hostname or hostname pattern (*)... see Config2
type Config struct {
	// These values need to agree or be intersected/unioned somehow for the listener.
	Enabled                  bool
	Ciphers                  []uint16
	PreferServerCipherSuites bool
	ClientAuth               tls.ClientAuthType
	ProtocolMinVersion       uint16
	ProtocolMaxVersion       uint16
	ClientCerts              []string

	// These can stay per-config (per-site)
	Manual     bool // will be set to true if user provides own certs and keys
	Managed    bool // will be set to true if config qualifies for implicit automatic/managed HTTPS
	OnDemand   bool // will be set to true if user enables on-demand TLS (obtain certs during handshakes)
	SelfSigned bool
	ACMEHost   string
	ACMEPort   string
	CAUrl      string

	// TODO: Experimenting...
	Hostname string // usually the hostname but could also contain wildcard; defines the class of names

	LetsEncryptEmail string
	KeyType          acme.KeyType
	DNSProvider      string

	// These settings take effect on a per-servername basis.
	// TODO: This would be better used in some sort of scoped GetCertificate function
	// SettingsByServerName map[string]struct {
	// 	LetsEncryptEmail string
	// 	KeyType          acme.KeyType
	// 	DNSProvider      string
	// }
}

// ObtainCert obtains a certificate for the hostname represented by info,
// as long as a certificate does not already exist in storage on disk. It
// only obtains and stores certificates (and their keys) to disk, it does
// not load them into memory. If allowPrompts is true, the user may be
// shown a prompt. If proxyACME is true, the relevant ACME challenges will
// be proxied to the alternate port.
// TODO - this function needs proxyACME to work, with custom alt port.
func (c *Config) ObtainCert(domain string, allowPrompts, proxyACME bool) error {
	if !c.Managed || !HostQualifies(c.Hostname) || existingCertAndKey(c.Hostname) {
		return nil
	}

	if c.LetsEncryptEmail == "" {
		c.LetsEncryptEmail = getEmail(allowPrompts)
	}

	client, err := newACMEClient(c, allowPrompts)
	if err != nil {
		return err
	}

	// TODO: DNS providers should be plugins too, so we don't
	// have to import them all, right??
	/*
		var dnsProv acme.ChallengeProvider
		var err error
		switch c.DNSProvider {
		case "cloudflare":
			dnsProv, err = cloudflare.NewDNSProvider()
		case "digitalocean":
			dnsProv, err = digitalocean.NewDNSProvider()
		case "dnsimple":
			dnsProv, err = dnsimple.NewDNSProvider()
		case "dyn":
			dnsProv, err = dyn.NewDNSProvider()
		case "gandi":
			dnsProv, err = gandi.NewDNSProvider()
		case "gcloud":
			dnsProv, err = gcloud.NewDNSProvider()
		case "namecheap":
			dnsProv, err = namecheap.NewDNSProvider()
		case "rfc2136":
			dnsProv, err = rfc2136.NewDNSProvider()
		case "route53":
			dnsProv, err = route53.NewDNSProvider()
		case "vultr":
			dnsProv, err = vultr.NewDNSProvider()
		}
		if err != nil {
			return err
		}
		if dnsProv != nil {
			client.SetChallengeProvider(acme.DNS01, dnsProv)
		}
	*/

	// client.Configure() assumes that allowPrompts == !proxyACME,
	// but that's not always true. For example, a restart where
	// the user isn't present and we're not listening on port 80.
	// So we don't call client.Configure() here...
	// TODO: This is the "old" way of doing it; this needs work still...
	if proxyACME {
		client.SetHTTPAddress(net.JoinHostPort(c.ACMEHost, c.ACMEPort))
		client.SetTLSAddress(net.JoinHostPort(c.ACMEHost, c.ACMEPort))
		//client.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01})
	} else {
		client.SetHTTPAddress(net.JoinHostPort(c.ACMEHost, c.ACMEPort))
		client.SetTLSAddress(net.JoinHostPort(c.ACMEHost, c.ACMEPort))
		//client.ExcludeChallenges([]acme.Challenge{acme.DNS01})
	}

	return client.Obtain([]string{domain})

	/*
		// We group infos by email so we don't make the same clients over and
		// over. This has the potential to prompt the user for an email, but we
		// prevent that by assuming that if we already have a listener that can
		// proxy ACME challenge requests, then the server is already running and
		// the operator is no longer present.
		groups := groupInfosByEmail(infos, allowPrompts)

		for email, group := range groups {
			// Wait as long as we can before creating the client, because it
			// may not be needed, for example, if we already have what we
			// need on disk. Creating a client involves the network and
			// potentially prompting the user, etc., so only do if necessary.
			var client *ACMEClient

			for _, info := range group {
				if !HostQualifies(info.Domain()) || existingCertAndKey(info.Domain()) {
					continue
				}

				// Now we definitely do need a client
				if client == nil {
					var err error
					client, err = NewACMEClient(email, allowPrompts)
					if err != nil {
						return errors.New("error creating client: " + err.Error())
					}
				}

				// client.Configure assumes that allowPrompts == !proxyACME,
				// but that's not always true. For example, a restart where
				// the user isn't present and we're not listening on port 80.
				// TODO: This is the "old" way of doing it; this needs work still.
				if proxyACME {
					client.SetHTTPAddress(info.ListenAddr())
					client.SetTLSAddress(info.ListenAddr())
					//client.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01})
				} else {
					client.SetHTTPAddress(info.ListenAddr())
					client.SetTLSAddress(info.ListenAddr())
					//client.ExcludeChallenges([]acme.Challenge{acme.DNS01})
				}

				err := client.Obtain([]string{info.Domain()})
				if err != nil {
					return err
				}
			}
		}

		return nil
	*/
}

// type Config struct {
// 		Rand io.Reader
// 		Time func() time.Time
// 		Certificates []Certificate
// 		NameToCertificate map[string]*Certificate
// 		GetCertificate func(clientHello *ClientHelloInfo) (*Certificate, error)
// 		RootCAs *x509.CertPool
// 		NextProtos []string
// 		ServerName string
// 		ClientAuth ClientAuthType
// 		ClientCAs *x509.CertPool
// 		InsecureSkipVerify bool
// 		CipherSuites []uint16
// 		PreferServerCipherSuites bool
// 		SessionTicketsDisabled bool
// 		SessionTicketKey [32]byte
// 		ClientSessionCache ClientSessionCache
// 		MinVersion uint16
// 		MaxVersion uint16
// 		CurvePreferences []CurveID
// }

// MakeTLSConfig reduces configs into a single tls.Config.
// If TLS is to be disabled, a nil tls.Config will be returned.
func MakeTLSConfig(configs []*Config) (*tls.Config, error) {
	if configs == nil || len(configs) == 0 {
		return nil, nil
	}

	config := new(tls.Config)
	ciphersAdded := make(map[uint16]struct{})
	configMap := make(configGroup)

	for i, cfg := range configs {
		if cfg == nil {
			// not invalid, but let's avoid nil pointer dereference below
			configs[i] = new(Config)
			continue
		}

		// TODO: What if cfg.Hostname is empty?

		// Key this config by its hostname; this
		// overwrites configs with the same hostname
		configMap[cfg.Hostname] = cfg

		// Can't serve TLS and not-TLS on same port
		if i > 0 && cfg.Enabled != configs[i-1].Enabled {
			thisConfProto, lastConfProto := "not TLS", "not TLS"
			if cfg.Enabled {
				thisConfProto = "TLS"
			}
			if configs[i-1].Enabled {
				lastConfProto = "TLS"
			}
			return nil, fmt.Errorf("cannot multiplex %s (%s) and %s (%s) on same listener",
				configs[i-1].Hostname, lastConfProto, cfg.Hostname, thisConfProto)
		}

		// Union cipher suites
		for _, ciph := range cfg.Ciphers {
			if _, ok := ciphersAdded[ciph]; !ok {
				ciphersAdded[ciph] = struct{}{}
				config.CipherSuites = append(config.CipherSuites, ciph)
			}
		}

		// Can't resolve conflicting PreferServerCipherSuites settings
		if i > 0 && cfg.PreferServerCipherSuites != configs[i-1].PreferServerCipherSuites {
			return nil, fmt.Errorf("cannot both PreferServerCipherSuites and not")
		}

		// Go with the widest range of protocol versions
		if cfg.ProtocolMinVersion < config.MinVersion {
			config.MinVersion = cfg.ProtocolMinVersion
		}
		if cfg.ProtocolMaxVersion < config.MaxVersion {
			config.MaxVersion = cfg.ProtocolMaxVersion
		}

		// Go with the strictest ClientAuth type
		if cfg.ClientAuth > config.ClientAuth {
			config.ClientAuth = cfg.ClientAuth
		}
	}

	// Is TLS disabled? If so, we're done here.
	// By now, we know that all configs agree
	// whether it is or not, so we can just look
	// at the first one.
	if !configs[0].Enabled {
		return nil, nil
	}

	// Default cipher suites
	if len(config.CipherSuites) == 0 {
		config.CipherSuites = defaultCiphers
	}

	// For security, ensure TLS_FALLBACK_SCSV is always included
	if config.CipherSuites[0] != tls.TLS_FALLBACK_SCSV {
		config.CipherSuites = append([]uint16{tls.TLS_FALLBACK_SCSV}, config.CipherSuites...)
	}

	// Set up client authentication if enabled
	if config.ClientAuth != tls.NoClientCert {
		pool := x509.NewCertPool()
		clientCertsAdded := make(map[string]struct{})
		for _, cfg := range configs {
			for _, caFile := range cfg.ClientCerts {
				// don't add cert to pool more than once
				if _, ok := clientCertsAdded[caFile]; ok {
					continue
				}
				clientCertsAdded[caFile] = struct{}{}

				// Any client with a certificate from this CA will be allowed to connect
				caCrt, err := ioutil.ReadFile(caFile)
				if err != nil {
					return nil, err
				}

				if !pool.AppendCertsFromPEM(caCrt) {
					return nil, fmt.Errorf("error loading client certificate '%s': no certificates were successfully parsed", caFile)
				}
			}
		}
		config.ClientCAs = pool
	}

	// Associate the GetCertificate callback, or nothing we just did will work
	config.GetCertificate = configMap.GetCertificate

	return config, nil
}

type GetCertificateCallback func(*tls.ClientHelloInfo) (*tls.Certificate, error)
