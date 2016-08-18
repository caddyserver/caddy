package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"log"
	"net/url"
	"strings"

	"github.com/mholt/caddy"
	"github.com/xenolf/lego/acme"
)

// Config describes how TLS should be configured and used.
type Config struct {
	// The hostname or class of hostnames this config is
	// designated for; can contain wildcard characters
	// according to RFC 6125 §6.4.3 - this field MUST
	// be set in order for things to work as expected
	Hostname string

	// Whether TLS is enabled
	Enabled bool

	// Minimum and maximum protocol versions to allow
	ProtocolMinVersion uint16
	ProtocolMaxVersion uint16

	// The list of cipher suites; first should be
	// TLS_FALLBACK_SCSV to prevent degrade attacks
	Ciphers []uint16

	// Whether to prefer server cipher suites
	PreferServerCipherSuites bool

	// Client authentication policy
	ClientAuth tls.ClientAuthType

	// List of client CA certificates to allow, if
	// client authentication is enabled
	ClientCerts []string

	// Manual means user provides own certs and keys
	Manual bool

	// Managed means config qualifies for implicit,
	// automatic, managed TLS; as opposed to the user
	// providing and managing the certificate manually
	Managed bool

	// OnDemand means the class of hostnames this
	// config applies to may obtain and manage
	// certificates at handshake-time (as opposed
	// to pre-loaded at startup); OnDemand certs
	// will be managed the same way as preloaded
	// ones, however, if an OnDemand cert fails to
	// renew, it is removed from the in-memory
	// cache; if this is true, Managed must
	// necessarily be true
	OnDemand bool

	// SelfSigned means that this hostname is
	// served with a self-signed certificate
	// that we generated in memory for convenience
	SelfSigned bool

	// The endpoint of the directory for the ACME
	// CA we are to use
	CAUrl string

	// The host (ONLY the host, not port) to listen
	// on if necessary to start a listener to solve
	// an ACME challenge
	ListenHost string

	// The alternate port (ONLY port, not host)
	// to use for the ACME HTTP challenge; this
	// port will be used if we proxy challenges
	// coming in on port 80 to this alternate port
	AltHTTPPort string

	// The string identifier of the DNS provider
	// to use when solving the ACME DNS challenge
	DNSProvider string

	// The email address to use when creating or
	// using an ACME account (fun fact: if this
	// is set to "off" then this config will not
	// qualify for managed TLS)
	ACMEEmail string

	// The type of key to use when generating
	// certificates
	KeyType acme.KeyType

	// The explicitly set storage creator or nil; use
	// StorageFor() to get a guaranteed non-nil Storage
	// instance. Note, Caddy may call this frequently so
	// implementors are encouraged to cache any heavy
	// instantiations.
	StorageCreator StorageCreator

	// The state needed to operate on-demand TLS
	OnDemandState OnDemandState
}

// OnDemandState contains some state relevant for providing
// on-demand TLS.
type OnDemandState struct {
	// The number of certificates that have been issued on-demand
	// by this config. It is only safe to modify this count atomically.
	// If it reaches MaxObtain, on-demand issuances must fail.
	ObtainedCount int32

	// Based on max_certs in tls config, it specifies the
	// maximum number of certificates that can be issued.
	MaxObtain int32
}

// ObtainCert obtains a certificate for c.Hostname, as long as a certificate
// does not already exist in storage on disk. It only obtains and stores
// certificates (and their keys) to disk, it does not load them into memory.
// If allowPrompts is true, the user may be shown a prompt. If proxyACME is
// true, the relevant ACME challenges will be proxied to the alternate port.
func (c *Config) ObtainCert(allowPrompts bool) error {
	return c.obtainCertName(c.Hostname, allowPrompts)
}

func (c *Config) obtainCertName(name string, allowPrompts bool) error {
	storage, err := c.StorageFor(c.CAUrl)
	if err != nil {
		return err
	}

	siteExists, err := storage.SiteExists(name)
	if err != nil {
		return err
	}

	if !c.Managed || !HostQualifies(name) || siteExists {
		return nil
	}

	// We must lock the obtain with the storage engine
	if lockObtained, err := storage.LockRegister(name); err != nil {
		return err
	} else if !lockObtained {
		log.Printf("[INFO] Certificate for %v is already being obtained elsewhere", name)
		return nil
	}
	defer func() {
		if err := storage.UnlockRegister(name); err != nil {
			log.Printf("[ERROR] Unable to unlock obtain lock for %v: %v", name, err)
		}
	}()

	if c.ACMEEmail == "" {
		c.ACMEEmail = getEmail(storage, allowPrompts)
	}

	client, err := newACMEClient(c, allowPrompts)
	if err != nil {
		return err
	}

	return client.Obtain([]string{name})
}

// RenewCert renews the certificate for c.Hostname. If there is already a lock
// on renewal, this will not perform the renewal and no error will occur.
func (c *Config) RenewCert(allowPrompts bool) error {
	return c.renewCertName(c.Hostname, allowPrompts)
}

// renewCertName renews the certificate for the given name. If there is already
// a lock on renewal, this will not perform the renewal and no error will
// occur.
func (c *Config) renewCertName(name string, allowPrompts bool) error {
	storage, err := c.StorageFor(c.CAUrl)
	if err != nil {
		return err
	}

	// We must lock the renewal with the storage engine
	if lockObtained, err := storage.LockRegister(name); err != nil {
		return err
	} else if !lockObtained {
		log.Printf("[INFO] Certificate for %v is already being renewed elsewhere", name)
		return nil
	}
	defer func() {
		if err := storage.UnlockRegister(name); err != nil {
			log.Printf("[ERROR] Unable to unlock renewal lock for %v: %v", name, err)
		}
	}()

	// Prepare for renewal (load PEM cert, key, and meta)
	siteData, err := storage.LoadSite(c.Hostname)
	if err != nil {
		return err
	}
	var certMeta acme.CertificateResource
	err = json.Unmarshal(siteData.Meta, &certMeta)
	certMeta.Certificate = siteData.Cert
	certMeta.PrivateKey = siteData.Key

	client, err := newACMEClient(c, allowPrompts)
	if err != nil {
		return err
	}

	// Perform renewal and retry if necessary, but not too many times.
	var newCertMeta acme.CertificateResource
	var success bool
	for attempts := 0; attempts < 2; attempts++ {
		namesObtaining.Add([]string{name})
		acmeMu.Lock()
		newCertMeta, err = client.RenewCertificate(certMeta, true)
		acmeMu.Unlock()
		namesObtaining.Remove([]string{name})
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

	return saveCertResource(storage, newCertMeta)
}

// StorageFor obtains a TLS Storage instance for the given CA URL which should
// be unique for every different ACME CA. If a StorageCreator is set on this
// Config, it will be used. Otherwise the default file storage implementation
// is used. When the error is nil, this is guaranteed to return a non-nil
// Storage instance.
func (c *Config) StorageFor(caURL string) (Storage, error) {
	// Validate CA URL
	if caURL == "" {
		caURL = DefaultCAUrl
	}
	if caURL == "" {
		return nil, fmt.Errorf("cannot create storage without CA URL")
	}
	caURL = strings.ToLower(caURL)

	// scheme required or host will be parsed as path (as of Go 1.6)
	if !strings.Contains(caURL, "://") {
		caURL = "https://" + caURL
	}

	u, err := url.Parse(caURL)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to parse CA URL: %v", caURL, err)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("%s: no host in CA URL", caURL)
	}

	// Create the storage based on the URL
	var s Storage
	if c.StorageCreator != nil {
		s, err = c.StorageCreator(u)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to create custom storage: %v", caURL, err)
		}
	}
	if s == nil {
		// We trust that this does not return a nil s when there's a nil err
		s, err = FileStorageCreator(u)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to create file storage: %v", caURL, err)
		}
	}
	return s, nil
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
			// avoid nil pointer dereference below
			configs[i] = new(Config)
			continue
		}

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
		if config.MinVersion == 0 || cfg.ProtocolMinVersion < config.MinVersion {
			config.MinVersion = cfg.ProtocolMinVersion
		}
		if cfg.ProtocolMaxVersion > config.MaxVersion {
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
	if len(configs) == 0 || !configs[0].Enabled {
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

	// Associate the GetCertificate callback, or almost nothing we just did will work
	config.GetCertificate = configMap.GetCertificate

	return config, nil
}

// ConfigGetter gets a Config keyed by key.
type ConfigGetter func(c *caddy.Controller) *Config

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
// including all but four of the suites below (the four GCM suites).
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
