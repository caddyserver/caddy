package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/xenolf/lego/acme"
)

// Config describes how TLS should be configured and used.
// TODO: Some of these should be scoped per hostname or hostname pattern (*)... see Config2
type Config struct {
	// These values are shared amongst other Configs for the same listener.
	Enabled                  bool
	Ciphers                  []uint16
	PreferServerCipherSuites bool
	ClientAuth               tls.ClientAuthType
	ProtocolMinVersion       uint16
	ProtocolMaxVersion       uint16
	ClientCerts              []string

	Manual     bool // will be set to true if user provides own certs and keys
	Managed    bool // will be set to true if config qualifies for implicit automatic/managed TLS
	OnDemand   bool // will be set to true if user enables on-demand TLS (obtain certs during handshakes)
	SelfSigned bool

	CAUrl string

	Hostname string // usually the hostname but could also contain wildcard; defines the class of names

	ListenHost  string // host only, not port
	AltHTTPPort string // port only, not host

	LetsEncryptEmail string
	KeyType          acme.KeyType
	DNSProvider      string
}

// ObtainCert obtains a certificate for c.Hostname, as long as a certificate
// does not already exist in storage on disk. It only obtains and stores
// certificates (and their keys) to disk, it does not load them into memory.
// If allowPrompts is true, the user may be shown a prompt. If proxyACME is
// true, the relevant ACME challenges will be proxied to the alternate port.
func (c *Config) ObtainCert(allowPrompts bool) error {
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

	return client.Obtain([]string{c.Hostname})
}

// RenewCert renews the certificate for c.Hostname.
func (c *Config) RenewCert(allowPrompts bool) error {
	// Prepare for renewal (load PEM cert, key, and meta)
	certBytes, err := ioutil.ReadFile(storage.SiteCertFile(c.Hostname))
	if err != nil {
		return err
	}
	keyBytes, err := ioutil.ReadFile(storage.SiteKeyFile(c.Hostname))
	if err != nil {
		return err
	}
	metaBytes, err := ioutil.ReadFile(storage.SiteMetaFile(c.Hostname))
	if err != nil {
		return err
	}
	var certMeta acme.CertificateResource
	err = json.Unmarshal(metaBytes, &certMeta)
	certMeta.Certificate = certBytes
	certMeta.PrivateKey = keyBytes

	client, err := newACMEClient(c, allowPrompts)
	if err != nil {
		return err
	}

	// Perform renewal and retry if necessary, but not too many times.
	var newCertMeta acme.CertificateResource
	var success bool
	for attempts := 0; attempts < 2; attempts++ {
		acmeMu.Lock()
		newCertMeta, err = client.RenewCertificate(certMeta, true)
		acmeMu.Unlock()
		if err == nil {
			success = true
			break
		}

		// If the legal terms were updated and need to be
		// agreed to again, we can handle that.
		if _, ok := err.(acme.TOSError); ok {
			err := client.AgreeToTOS()
			if err != nil {
				return err
			}
			continue
		}

		// For any other kind of error, wait 10s and try again.
		time.Sleep(10 * time.Second)
	}

	if !success {
		return errors.New("too many renewal attempts; last error: " + err.Error())
	}

	return saveCertResource(newCertMeta)
}

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
			// not an error, but let's avoid nil pointer dereference below
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
			return nil, fmt.Errorf("cannot both use PreferServerCipherSuites and not use it")
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

// ConfigGetter gets a Config keyed by key.
type ConfigGetter func(key string) *Config

var configGetters = make(map[string]ConfigGetter)

// RegisterConfigGetter registers fn as the way to get a
// Config for server type serverType.
func RegisterConfigGetter(serverType string, fn ConfigGetter) {
	configGetters[serverType] = fn
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

// GetCertificateCallback is a function that can be used as a tls.Config.GetCertificate
// callback. TODO: Not used!?
type GetCertificateCallback func(*tls.ClientHelloInfo) (*tls.Certificate, error)

const (
	// HTTPChallengePort is the officially designated port for
	// the HTTP challenge.
	HTTPChallengePort = "80"

	// TLSSNIChallengePort is the officially designated port for
	// the TLS-SNI challenge.
	TLSSNIChallengePort = "443"

	// DefaultHTTPAlternatePort is the port on which the ACME
	// client will open a listener and solve the HTTP challenge.
	// If this alternate port is used instead of the default
	// port, then whatever is listening on the default port must
	// be capable of proxying or forwarding the request to this
	// alternate port.
	DefaultHTTPAlternatePort = "5033"
)
