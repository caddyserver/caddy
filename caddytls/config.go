// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
	"github.com/klauspost/cpuid"
	"github.com/mholt/certmagic"
)

// Config describes how TLS should be configured and used.
type Config struct {
	// The hostname or class of hostnames this config is
	// designated for; can contain wildcard characters
	// according to RFC 6125 §6.4.3 - this field MUST
	// be set in order for things to work as expected,
	// must be normalized, and if an IP address, must
	// be normalized
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

	// The list of preferred curves
	CurvePreferences []tls.CurveID

	// Client authentication policy
	ClientAuth tls.ClientAuthType

	// List of client CA certificates to allow, if
	// client authentication is enabled
	ClientCerts []string

	// Allow mismatched TLS SNI and Host header when using TLS client authentication
	// If false (the default), the Host header in the HTTP request must
	// match the SNI value in the TLS handshake (if any).
	// This should be enabled whenever the TLS SNI and Host header
	// in the HTTP request can be different, for example when doing mTLS with multiple servers
	// and the upstream addresses do not match the HTTP request Host header.
	// If a site relies on TLS client authentication or any time you want to enforce that THIS site's TLS config
	// is used and not the TLS config of any other site
	// on the same listener, set this to false.
	// TODO: Check how relevant this is with TLS 1.3.
	InsecureDisableSNIMatching bool

	// Manual means user provides own certs and keys
	Manual bool

	// Managed means this config should be managed
	// by the CertMagic Config (Manager field)
	Managed bool

	// Manager is how certificates are managed
	Manager *certmagic.Config

	// SelfSigned means that this hostname is
	// served with a self-signed certificate
	// that we generated in memory for convenience
	SelfSigned bool

	// The email address to use when creating or
	// using an ACME account (fun fact: if this
	// is set to "off" then this config will not
	// qualify for managed TLS)
	ACMEEmail string

	// The list of protocols to choose from for Application Layer
	// Protocol Negotiation (ALPN).
	ALPN []string

	// The final tls.Config created with
	// buildStandardTLSConfig()
	tlsConfig *tls.Config
}

// NewConfig returns a new Config with a pointer to the instance's
// certificate cache. You will usually need to set other fields on
// the returned Config for successful practical use.
func NewConfig(inst *caddy.Instance) (*Config, error) {
	inst.StorageMu.RLock()
	certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certmagic.Cache)
	inst.StorageMu.RUnlock()
	if !ok || certCache == nil {
		if err := makeClusteringPlugin(); err != nil {
			return nil, err
		}
		certCache = certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (certmagic.Config, error) {
				inst.StorageMu.RLock()
				cfgMap, ok := inst.Storage[configMapKey].(map[string]*Config)
				inst.StorageMu.RUnlock()
				if ok {
					for hostname, cfg := range cfgMap {
						if cfg.Manager != nil && hostname == cert.Names[0] {
							return *cfg.Manager, nil
						}
					}
				}
				return certmagic.Default, nil
			},
		})

		storageCleaningTicker := time.NewTicker(12 * time.Hour)
		done := make(chan bool)
		go func() {
			for {
				select {
				case <-done:
					storageCleaningTicker.Stop()
					return
				case <-storageCleaningTicker.C:
					certmagic.CleanStorage(certmagic.Default.Storage, certmagic.CleanStorageOptions{
						OCSPStaples: true,
					})
				}
			}
		}()
		inst.OnShutdown = append(inst.OnShutdown, func() error {
			certCache.Stop()
			done <- true
			close(done)
			return nil
		})

		inst.StorageMu.Lock()
		inst.Storage[CertCacheInstStorageKey] = certCache
		inst.StorageMu.Unlock()
	}
	return &Config{
		Manager: certmagic.New(certCache, certmagic.Config{}),
	}, nil
}

// buildStandardTLSConfig converts cfg (*caddytls.Config) to a *tls.Config
// and stores it in cfg so it can be used in servers. If TLS is disabled,
// no tls.Config is created.
func (c *Config) buildStandardTLSConfig() error {
	if !c.Enabled {
		return nil
	}

	config := new(tls.Config)

	ciphersAdded := make(map[uint16]struct{})
	curvesAdded := make(map[tls.CurveID]struct{})

	// add cipher suites
	for _, ciph := range c.Ciphers {
		if _, ok := ciphersAdded[ciph]; !ok {
			ciphersAdded[ciph] = struct{}{}
			config.CipherSuites = append(config.CipherSuites, ciph)
		}
	}

	config.PreferServerCipherSuites = c.PreferServerCipherSuites

	// add curve preferences
	for _, curv := range c.CurvePreferences {
		if _, ok := curvesAdded[curv]; !ok {
			curvesAdded[curv] = struct{}{}
			config.CurvePreferences = append(config.CurvePreferences, curv)
		}
	}

	// ensure ALPN includes the ACME TLS-ALPN protocol
	var alpnFound bool
	for _, a := range c.ALPN {
		if a == tlsalpn01.ACMETLS1Protocol {
			alpnFound = true
			break
		}
	}
	if !alpnFound {
		c.ALPN = append(c.ALPN, tlsalpn01.ACMETLS1Protocol)
	}

	config.MinVersion = c.ProtocolMinVersion
	config.MaxVersion = c.ProtocolMaxVersion
	config.ClientAuth = c.ClientAuth
	config.NextProtos = c.ALPN
	config.GetCertificate = c.Manager.GetCertificate

	// set up client authentication if enabled
	if config.ClientAuth != tls.NoClientCert {
		pool := x509.NewCertPool()
		clientCertsAdded := make(map[string]struct{})

		for _, caFile := range c.ClientCerts {
			// don't add cert to pool more than once
			if _, ok := clientCertsAdded[caFile]; ok {
				continue
			}
			clientCertsAdded[caFile] = struct{}{}

			// Any client with a certificate from this CA will be allowed to connect
			caCrt, err := ioutil.ReadFile(caFile)
			if err != nil {
				return err
			}

			if !pool.AppendCertsFromPEM(caCrt) {
				return fmt.Errorf("error loading client certificate '%s': no certificates were successfully parsed", caFile)
			}
		}

		config.ClientCAs = pool
	}

	// default cipher suites
	if len(config.CipherSuites) == 0 {
		config.CipherSuites = getPreferredDefaultCiphers()
	}

	// for security, ensure TLS_FALLBACK_SCSV is always included first
	if len(config.CipherSuites) == 0 || config.CipherSuites[0] != tls.TLS_FALLBACK_SCSV {
		config.CipherSuites = append([]uint16{tls.TLS_FALLBACK_SCSV}, config.CipherSuites...)
	}

	// store the resulting new tls.Config
	c.tlsConfig = config

	return nil
}

// MakeTLSConfig makes a tls.Config from configs. The returned
// tls.Config is programmed to load the matching caddytls.Config
// based on the hostname in SNI, but that's all. This is used
// to create a single TLS configuration for a listener (a group
// of sites).
func MakeTLSConfig(configs []*Config) (*tls.Config, error) {
	if len(configs) == 0 {
		return nil, nil
	}

	configMap := make(configGroup)

	for i, cfg := range configs {
		if cfg == nil {
			// avoid nil pointer dereference below this loop
			configs[i] = new(Config)
			continue
		}

		// can't serve TLS and non-TLS on same port
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

		// convert this caddytls.Config into a tls.Config
		if err := cfg.buildStandardTLSConfig(); err != nil {
			return nil, err
		}

		// if an existing config with this hostname was already
		// configured, then they must be identical (or at least
		// compatible), otherwise that is a configuration error
		if otherConfig, ok := configMap[cfg.Hostname]; ok {
			if err := assertConfigsCompatible(cfg, otherConfig); err != nil {
				return nil, fmt.Errorf("incompatible TLS configurations for the same SNI "+
					"name (%s) on the same listener: %v",
					cfg.Hostname, err)
			}
		}

		// key this config by its hostname (overwrites
		// configs with the same hostname pattern; should
		// be OK since we already asserted they are roughly
		// the same); during TLS handshakes, configs are
		// loaded based on the hostname pattern according
		// to client's ServerName (SNI) value
		if cfg.Hostname == "0.0.0.0" || cfg.Hostname == "::" {
			configMap[""] = cfg
		} else {
			configMap[cfg.Hostname] = cfg
		}
	}

	// Is TLS disabled? By now, we know that all
	// configs agree whether it is or not, so we
	// can just look at the first one. If so,
	// we're done here.
	if len(configs) == 0 || !configs[0].Enabled {
		return nil, nil
	}

	return &tls.Config{
		// A tls.Config must have Certificates or GetCertificate
		// set, in order to be accepted by tls.Listen and quic.Listen.
		// TODO: remove this once the standard library allows a tls.Config with
		// only GetConfigForClient set. https://github.com/caddyserver/caddy/pull/2404
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, fmt.Errorf("all certificates configured via GetConfigForClient")
		},
		GetConfigForClient: configMap.GetConfigForClient,
	}, nil
}

// assertConfigsCompatible returns an error if the two Configs
// do not have the same (or roughly compatible) configurations.
// If one of the tlsConfig pointers on either Config is nil,
// an error will be returned. If both are nil, no error.
func assertConfigsCompatible(cfg1, cfg2 *Config) error {
	c1, c2 := cfg1.tlsConfig, cfg2.tlsConfig

	if (c1 == nil && c2 != nil) || (c1 != nil && c2 == nil) {
		return fmt.Errorf("one config is not made")
	}
	if c1 == nil && c2 == nil {
		return nil
	}

	if len(c1.CipherSuites) != len(c2.CipherSuites) {
		return fmt.Errorf("different number of allowed cipher suites")
	}
	for i, ciph := range c1.CipherSuites {
		if c2.CipherSuites[i] != ciph {
			return fmt.Errorf("different cipher suites or different order")
		}
	}

	if len(c1.CurvePreferences) != len(c2.CurvePreferences) {
		return fmt.Errorf("different number of allowed cipher suites")
	}
	for i, curve := range c1.CurvePreferences {
		if c2.CurvePreferences[i] != curve {
			return fmt.Errorf("different curve preferences or different order")
		}
	}

	if len(c1.NextProtos) != len(c2.NextProtos) {
		return fmt.Errorf("different number of ALPN (NextProtos) values")
	}
	for i, proto := range c1.NextProtos {
		if c2.NextProtos[i] != proto {
			return fmt.Errorf("different ALPN (NextProtos) values or different order")
		}
	}

	if c1.PreferServerCipherSuites != c2.PreferServerCipherSuites {
		return fmt.Errorf("one prefers server cipher suites, the other does not")
	}
	if c1.MinVersion != c2.MinVersion {
		return fmt.Errorf("minimum TLS version mismatch")
	}
	if c1.MaxVersion != c2.MaxVersion {
		return fmt.Errorf("maximum TLS version mismatch")
	}

	if err := assertClientCertsCompatible(cfg1, cfg2); err != nil {
		return err
	}

	return nil
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
		config.Ciphers = getPreferredDefaultCiphers()
	}

	// Not a cipher suite, but still important for mitigating protocol downgrade attacks
	// (prepend since having it at end breaks http2 due to non-h2-approved suites before it)
	config.Ciphers = append([]uint16{tls.TLS_FALLBACK_SCSV}, config.Ciphers...)

	// If no curves provided, use default list
	if len(config.CurvePreferences) == 0 {
		config.CurvePreferences = defaultCurves
	}

	// Set default protocol min and max versions - must balance compatibility and security
	if config.ProtocolMinVersion == 0 {
		config.ProtocolMinVersion = tls.VersionTLS12
	}
	if config.ProtocolMaxVersion == 0 {
		config.ProtocolMaxVersion = tls.VersionTLS13
	}

	// Prefer server cipher suites
	config.PreferServerCipherSuites = true
}

// Map of supported key types
var supportedKeyTypes = map[string]certcrypto.KeyType{
	"P384":    certcrypto.EC384,
	"P256":    certcrypto.EC256,
	"RSA4096": certcrypto.RSA4096,
	"RSA2048": certcrypto.RSA2048,
}

// SupportedProtocols is a map of supported protocols.
// HTTP/2 only supports TLS 1.2 and higher.
// If updating this map, also update tlsProtocolStringToMap in caddyhttp/fastcgi/fastcgi.go
var SupportedProtocols = map[string]uint16{
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
	"tls1.2": tls.VersionTLS12,
	"tls1.3": tls.VersionTLS13,
}

// GetSupportedProtocolName returns the protocol name
func GetSupportedProtocolName(protocol uint16) (string, error) {
	for k, v := range SupportedProtocols {
		if v == protocol {
			return k, nil
		}
	}

	return "", fmt.Errorf("name: unsupported protocol")
}

// SupportedCiphersMap has supported ciphers, used only for parsing config.
//
// Note that, at time of writing, HTTP/2 blacklists 276 cipher suites,
// including all but four of the suites below (the four GCM suites).
// See https://http2.github.io/http2-spec/#BadCipherSuites
//
// TLS_FALLBACK_SCSV is not in this list because we manually ensure
// it is always added (even though it is not technically a cipher suite).
//
// This map, like any map, is NOT ORDERED. Do not range over this map.
var SupportedCiphersMap = map[string]uint16{
	"ECDHE-ECDSA-AES256-GCM-SHA384":      tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES256-GCM-SHA384":        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-AES128-GCM-SHA256":      tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES128-GCM-SHA256":        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-WITH-CHACHA20-POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"ECDHE-RSA-WITH-CHACHA20-POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"ECDHE-RSA-AES256-CBC-SHA":           tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE-RSA-AES128-CBC-SHA":           tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-ECDSA-AES256-CBC-SHA":         tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE-ECDSA-AES128-CBC-SHA":         tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"RSA-AES256-CBC-SHA":                 tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"RSA-AES128-CBC-SHA":                 tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-RSA-3DES-EDE-CBC-SHA":         tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"RSA-3DES-EDE-CBC-SHA":               tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// GetSupportedCipherName returns the cipher name
func GetSupportedCipherName(cipher uint16) (string, error) {
	for k, v := range SupportedCiphersMap {
		if v == cipher {
			return k, nil
		}
	}

	return "", fmt.Errorf("name: unsupported cipher")
}

// List of all the ciphers we want to use by default
var defaultCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// List of ciphers we should prefer if native AESNI support is missing
var defaultCiphersNonAESNI = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// getPreferredDefaultCiphers returns an appropriate cipher suite to use, depending on
// the hardware support available for AES-NI.
//
// See https://github.com/caddyserver/caddy/issues/1674
func getPreferredDefaultCiphers() []uint16 {
	if cpuid.CPU.AesNi() {
		return defaultCiphers
	}

	// Return a cipher suite that prefers ChaCha20
	return defaultCiphersNonAESNI
}

func assertClientCertsCompatible(cfg1, cfg2 *Config) error {
	c1, c2 := cfg1.tlsConfig, cfg2.tlsConfig
	if c1.ClientAuth != c2.ClientAuth {
		return fmt.Errorf("client authentication policy mismatch")
	}

	if c1.ClientAuth == tls.NoClientCert || c2.ClientAuth == tls.NoClientCert {
		return nil
	}

	ccerts1, ccerts2 := cfg1.ClientCerts, cfg2.ClientCerts

	if len(ccerts1) != len(ccerts2) {
		return fmt.Errorf("number of client certs differs")
	}

	// The order of client CAs matters
	for i, v := range ccerts1 {
		if v != ccerts2[i] {
			// Two hosts defined on the same listener are not compatible if they
			// have ClientAuth enabled, because there's no guarantee beyond the
			// hostname which config will be used (because SNI only has server name).
			// To prevent clients from bypassing authentication, require that
			// ClientAuth be configured in an unambiguous manner.
			return fmt.Errorf("multiple hosts requiring client authentication ambiguously configured")
		}
	}

	return nil
}

// Map of supported curves
// https://golang.org/pkg/crypto/tls/#CurveID
var supportedCurvesMap = map[string]tls.CurveID{
	"X25519": tls.X25519,
	"P256":   tls.CurveP256,
	"P384":   tls.CurveP384,
	"P521":   tls.CurveP521,
}

// List of all the curves we want to use by default.
//
// This list should only include curves which are fast by design (e.g. X25519)
// and those for which an optimized assembly implementation exists (e.g. P256).
// The latter ones can be found here: https://github.com/golang/go/tree/master/src/crypto/elliptic
var defaultCurves = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
}

var clusterPluginSetup int32 // access atomically

// CertCacheInstStorageKey is the name of the key for
// accessing the certificate storage on the *caddy.Instance.
const CertCacheInstStorageKey = "tls_cert_cache"
