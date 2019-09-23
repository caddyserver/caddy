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
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/telemetry"
	"github.com/mholt/certmagic"
)

func init() {
	// opt-in TLS 1.3 for Go1.12
	// TODO: remove this line when Go1.13 is released.
	if err := os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1"); err != nil {
		log.Println("[ERROR] failed to set environment variable: ", err)
	}

	caddy.RegisterPlugin("tls", caddy.Plugin{Action: setupTLS})

	// ensure the default Storage implementation is plugged in
	RegisterClusterPlugin("file", constructDefaultClusterPlugin)
}

// setupTLS sets up the TLS configuration and installs certificates that
// are specified by the user in the config file. All the automatic HTTPS
// stuff comes later outside of this function.
func setupTLS(c *caddy.Controller) error {
	if err := makeClusteringPlugin(); err != nil {
		return err
	}

	configGetter, ok := configGetters[c.ServerType()]
	if !ok {
		return fmt.Errorf("no caddytls.ConfigGetter for %s server type; must call RegisterConfigGetter", c.ServerType())
	}
	config := configGetter(c)
	if config == nil {
		return fmt.Errorf("no caddytls.Config to set up for %s", c.Key)
	}

	config.Enabled = true

	// we use certmagic events to collect metrics for telemetry
	config.Manager.OnEvent = func(event string, data interface{}) {
		switch event {
		case "tls_handshake_started":
			clientHello := data.(*tls.ClientHelloInfo)
			if ClientHelloTelemetry && len(clientHello.SupportedVersions) > 0 {
				// If no other plugin (such as the HTTP server type) is implementing ClientHello telemetry, we do it.
				// NOTE: The values in the Go standard lib's ClientHelloInfo aren't guaranteed to be in order.
				info := ClientHelloInfo{
					Version:                   clientHello.SupportedVersions[0], // report the highest
					CipherSuites:              clientHello.CipherSuites,
					ExtensionsUnknown:         true, // no extension info... :(
					CompressionMethodsUnknown: true, // no compression methods... :(
					Curves:                    clientHello.SupportedCurves,
					Points:                    clientHello.SupportedPoints,
					// We also have, but do not yet use: SignatureSchemes, ServerName, and SupportedProtos (ALPN)
					// because the standard lib parses some extensions, but our MITM detector generally doesn't.
				}
				go telemetry.SetNested("tls_client_hello", info.Key(), info)
			}

		case "tls_handshake_completed":
			// TODO: This is a "best guess" for now - at this point, we only gave a
			// certificate to the client; we need something listener-level to be sure
			go telemetry.Increment("tls_handshake_count")

		case "acme_cert_obtained":
			go telemetry.Increment("tls_acme_certs_obtained")

		case "acme_cert_renewed":
			name := data.(string)
			caddy.EmitEvent(caddy.CertRenewEvent, name)
			go telemetry.Increment("tls_acme_certs_renewed")

		case "acme_cert_revoked":
			telemetry.Increment("acme_certs_revoked")

		case "cached_managed_cert":
			telemetry.Increment("tls_managed_cert_count")

		case "cached_unmanaged_cert":
			telemetry.Increment("tls_unmanaged_cert_count")
		}
	}

	for c.Next() {
		var certificateFile, keyFile, loadDir, maxCerts, askURL string
		var onDemand bool

		args := c.RemainingArgs()
		switch len(args) {
		case 1:
			// even if the email is one of the special values below,
			// it is still necessary for future analysis that we store
			// that value in the ACMEEmail field.
			config.ACMEEmail = args[0]

			switch args[0] {
			// user can force-disable managed TLS this way
			case "off":
				config.Enabled = false
				return nil
			// user might want a temporary, in-memory, self-signed cert
			case "self_signed":
				config.SelfSigned = true
			default:
				config.Manager.Email = args[0]
			}
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
			case "ca":
				arg := c.RemainingArgs()
				if len(arg) != 1 {
					return c.ArgErr()
				}
				config.Manager.CA = arg[0]
			case "key_type":
				arg := c.RemainingArgs()
				value, ok := supportedKeyTypes[strings.ToUpper(arg[0])]
				if !ok {
					return c.Errf("Wrong key type name or key type not supported: '%s'", c.Val())
				}
				config.Manager.KeyType = value
			case "protocols":
				args := c.RemainingArgs()
				if len(args) == 1 {
					value, ok := SupportedProtocols[strings.ToLower(args[0])]
					if !ok {
						return c.Errf("Wrong protocol name or protocol not supported: '%s'", args[0])
					}
					config.ProtocolMinVersion, config.ProtocolMaxVersion = value, value
				} else {
					value, ok := SupportedProtocols[strings.ToLower(args[0])]
					if !ok {
						return c.Errf("Wrong protocol name or protocol not supported: '%s'", args[0])
					}
					config.ProtocolMinVersion = value
					value, ok = SupportedProtocols[strings.ToLower(args[1])]
					if !ok {
						return c.Errf("Wrong protocol name or protocol not supported: '%s'", args[1])
					}
					config.ProtocolMaxVersion = value
					if config.ProtocolMinVersion > config.ProtocolMaxVersion {
						return c.Errf("Minimum protocol version cannot be higher than maximum (reverse the order)")
					}
				}
			case "ciphers":
				for c.NextArg() {
					value, ok := SupportedCiphersMap[strings.ToUpper(c.Val())]
					if !ok {
						return c.Errf("Wrong cipher name or cipher not supported: '%s'", c.Val())
					}
					config.Ciphers = append(config.Ciphers, value)
				}
			case "curves":
				for c.NextArg() {
					value, ok := supportedCurvesMap[strings.ToUpper(c.Val())]
					if !ok {
						return c.Errf("Wrong curve name or curve not supported: '%s'", c.Val())
					}
					config.CurvePreferences = append(config.CurvePreferences, value)
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
				onDemand = true
			case "ask":
				c.Args(&askURL)
				onDemand = true
			case "dns":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				// TODO: we can get rid of DNS provider plugins with this one line
				// of code; however, currently (Dec. 2018) this adds about 20 MB
				// of bloat to the Caddy binary, doubling its size to ~40 MB...!
				// dnsProv, err := dns.NewDNSChallengeProviderByName(args[0])
				// if err != nil {
				// 	return c.Errf("Configuring DNS provider '%s': %v", args[0], err)
				// }
				dnsProvName := args[0]
				dnsProvConstructor, ok := dnsProviders[dnsProvName]
				if !ok {
					return c.Errf("Unknown DNS provider by name '%s'", dnsProvName)
				}
				dnsProv, err := dnsProvConstructor()
				if err != nil {
					return c.Errf("Setting up DNS provider '%s': %v", dnsProvName, err)
				}
				config.Manager.DNSProvider = dnsProv
			case "alpn":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return c.ArgErr()
				}
				for _, arg := range args {
					config.ALPN = append(config.ALPN, arg)
				}
			case "must_staple":
				config.Manager.MustStaple = true
			case "wildcard":
				if !certmagic.HostQualifies(config.Hostname) {
					return c.Errf("Hostname '%s' does not qualify for managed TLS, so cannot manage wildcard certificate for it", config.Hostname)
				}
				if strings.Contains(config.Hostname, "*") {
					return c.Errf("Cannot convert domain name '%s' to a valid wildcard: already has a wildcard label", config.Hostname)
				}
				parts := strings.Split(config.Hostname, ".")
				if len(parts) < 3 {
					return c.Errf("Cannot convert domain name '%s' to a valid wildcard: too few labels", config.Hostname)
				}
				parts[0] = "*"
				config.Hostname = strings.Join(parts, ".")
			default:
				return c.Errf("Unknown subdirective '%s'", c.Val())
			}
		}

		// tls requires at least one argument if a block is not opened
		if len(args) == 0 && !hadBlock {
			return c.ArgErr()
		}

		// configure on-demand TLS, if enabled
		if onDemand {
			config.Manager.OnDemand = new(certmagic.OnDemandConfig)
			if maxCerts != "" {
				log.Println("[WARNING] The max_certs subdirective is now deprecated and offers no protection; please use ask instead.")
				fmt.Printf("WARNING: The max_certs subdirective is now deprecated and offers no protection; please use ask instead.")
			}
			if askURL != "" {
				parsedURL, err := url.Parse(askURL)
				if err != nil {
					return c.Err("ask must be a valid url")
				}
				if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
					return c.Err("ask URL must use http or https")
				}
				config.Manager.OnDemand.DecisionFunc = func(name string) error {
					askURLParsed, err := url.Parse(askURL)
					if err != nil {
						return fmt.Errorf("parsing ask URL: %v", err)
					}
					qs := askURLParsed.Query()
					qs.Set("domain", name)
					askURLParsed.RawQuery = qs.Encode()

					resp, err := onDemandAskClient.Get(askURLParsed.String())
					if err != nil {
						return fmt.Errorf("error checking %v to determine if certificate for hostname '%s' should be allowed: %v",
							askURL, name, err)
					}
					resp.Body.Close()

					if resp.StatusCode < 200 || resp.StatusCode > 299 {
						return fmt.Errorf("certificate for hostname '%s' not allowed; non-2xx status code %d returned from %v",
							name, resp.StatusCode, askURL)
					}

					return nil
				}
			}
		}

		// don't try to load certificates unless we're supposed to
		if !config.Enabled || !config.Manual {
			continue
		}

		// load a single certificate and key, if specified
		if certificateFile != "" && keyFile != "" {
			err := config.Manager.CacheUnmanagedCertificatePEMFile(certificateFile, keyFile, nil)
			if err != nil {
				return c.Errf("Unable to load certificate and key files for '%s': %v", c.Key, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s and %s", certificateFile, keyFile)
		}

		// load a directory of certificates, if specified
		if loadDir != "" {
			err := loadCertsInDir(config, c, loadDir)
			if err != nil {
				return err
			}
		}
	}

	SetDefaultTLSParams(config)

	// generate self-signed cert if needed
	if config.SelfSigned {
		ssCert, err := newSelfSignedCertificate(selfSignedConfig{
			SAN:     []string{config.Hostname},
			KeyType: config.Manager.KeyType,
		})
		if err != nil {
			return fmt.Errorf("self-signed certificate generation: %v", err)
		}
		err = config.Manager.CacheUnmanagedTLSCertificate(ssCert, nil)
		if err != nil {
			return fmt.Errorf("self-signed: %v", err)
		}
		telemetry.Increment("tls_self_signed_count")
	}

	// store this as a custom config
	cfgMap, ok := c.Get(configMapKey).(map[string]*Config)
	if !ok || cfgMap == nil {
		cfgMap = make(map[string]*Config)
	}
	cfgMap[config.Hostname] = config
	c.Set(configMapKey, cfgMap)

	return nil
}

// loadCertsInDir loads all the certificates/keys in dir, as long as
// the file ends with .pem. This method of loading certificates is
// modeled after haproxy, which expects the certificate and key to
// be bundled into the same file:
// https://cbonte.github.io/haproxy-dconv/configuration-1.5.html#5.1-crt
//
// This function may write to the log as it walks the directory tree.
func loadCertsInDir(cfg *Config, c *caddy.Controller, dir string) error {
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
					if err := pem.Encode(certBuilder, derBlock); err != nil {
						log.Println("[ERROR] failed to write PEM encoding: ", err)
					}
				} else if derBlock.Type == "EC PARAMETERS" {
					// EC keys generated from openssl can be composed of two blocks:
					// parameters and key (parameter block should come first)
					if !foundKey {
						// Encode parameters
						if err := pem.Encode(keyBuilder, derBlock); err != nil {
							log.Println("[ERROR] failed to write PEM encoding: ", err)
						}

						// Key must immediately follow
						derBlock, bundle = pem.Decode(bundle)
						if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
							return c.Errf("%s: expected elliptic private key to immediately follow EC parameters", path)
						}
						if err := pem.Encode(keyBuilder, derBlock); err != nil {
							log.Println("[ERROR] failed to write PEM encoding: ", err)
						}
						foundKey = true
					}
				} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
					// RSA key
					if !foundKey {
						if err := pem.Encode(keyBuilder, derBlock); err != nil {
							log.Println("[ERROR] failed to write PEM encoding: ", err)
						}
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

			err = cfg.Manager.CacheUnmanagedCertificatePEMBytes(certPEMBytes, keyPEMBytes, nil)
			if err != nil {
				return c.Errf("%s: failed to load cert and key for '%s': %v", path, c.Key, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s", path)
		}
		return nil
	})
}

func makeClusteringPlugin() error {
	// set up the clustering plugin, if there is one (and there should always
	// be one since this tls plugin requires it) -- this should be done exactly
	// once, but we can't do it during init while plugins are still registering,
	// so do it as soon as we run a setup)
	if atomic.CompareAndSwapInt32(&clusterPluginSetup, 0, 1) {
		clusterPluginName := os.Getenv("CADDY_CLUSTERING")
		if clusterPluginName == "" {
			clusterPluginName = "file" // name of default storage plugin
		}
		clusterFn, ok := clusterProviders[clusterPluginName]
		if ok {
			storage, err := clusterFn()
			if err != nil {
				return fmt.Errorf("constructing cluster plugin %s: %v", clusterPluginName, err)
			}
			certmagic.Default.Storage = storage
		} else {
			return fmt.Errorf("unrecognized cluster plugin (was it included in the Caddy build?): %s", clusterPluginName)
		}
	}
	return nil
}

func constructDefaultClusterPlugin() (certmagic.Storage, error) {
	return &certmagic.FileStorage{Path: caddy.AssetsPath()}, nil
}

var onDemandAskClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("following http redirects is not allowed")
	},
}

const configMapKey = "tls_custom_configs"
