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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("tls", caddy.Plugin{Action: setupTLS})
}

// setupTLS sets up the TLS configuration and installs certificates that
// are specified by the user in the config file. All the automatic HTTPS
// stuff comes later outside of this function.
func setupTLS(c *caddy.Controller) error {
	// obtain the configGetter, which loads the config we're, uh, configuring
	configGetter, ok := configGetters[c.ServerType()]
	if !ok {
		return fmt.Errorf("no caddytls.ConfigGetter for %s server type; must call RegisterConfigGetter", c.ServerType())
	}
	config := configGetter(c)
	if config == nil {
		return fmt.Errorf("no caddytls.Config to set up for %s", c.Key)
	}

	// the certificate cache is tied to the current caddy.Instance; get a pointer to it
	certCache, ok := c.Get(CertCacheInstStorageKey).(*certificateCache)
	if !ok || certCache == nil {
		certCache = &certificateCache{cache: make(map[string]Certificate)}
		c.Set(CertCacheInstStorageKey, certCache)
	}
	config.certCache = certCache

	config.Enabled = true

	for c.Next() {
		var certificateFile, keyFile, loadDir, maxCerts, askURL string

		args := c.RemainingArgs()
		switch len(args) {
		case 1:
			// even if the email is one of the special values below,
			// it is still necessary for future analysis that we store
			// that value in the ACMEEmail field.
			config.ACMEEmail = args[0]

			// user can force-disable managed TLS this way
			if args[0] == "off" {
				config.Enabled = false
				return nil
			}

			// user might want a temporary, in-memory, self-signed cert
			if args[0] == "self_signed" {
				config.SelfSigned = true
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
				config.CAUrl = arg[0]
			case "key_type":
				arg := c.RemainingArgs()
				value, ok := supportedKeyTypes[strings.ToUpper(arg[0])]
				if !ok {
					return c.Errf("Wrong key type name or key type not supported: '%s'", c.Val())
				}
				config.KeyType = value
			case "protocols":
				args := c.RemainingArgs()
				if len(args) == 1 {
					value, ok := supportedProtocols[strings.ToLower(args[0])]
					if !ok {
						return c.Errf("Wrong protocol name or protocol not supported: '%s'", args[0])
					}

					config.ProtocolMinVersion, config.ProtocolMaxVersion = value, value
				} else {
					value, ok := supportedProtocols[strings.ToLower(args[0])]
					if !ok {
						return c.Errf("Wrong protocol name or protocol not supported: '%s'", args[0])
					}
					config.ProtocolMinVersion = value
					value, ok = supportedProtocols[strings.ToLower(args[1])]
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
					value, ok := supportedCiphersMap[strings.ToUpper(c.Val())]
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
				config.OnDemand = true
			case "ask":
				c.Args(&askURL)
				config.OnDemand = true
			case "dns":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				dnsProvName := args[0]
				if _, ok := dnsProviders[dnsProvName]; !ok {
					return c.Errf("Unsupported DNS provider '%s'", args[0])
				}
				config.DNSProvider = args[0]
			case "storage":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				storageProvName := args[0]
				if _, ok := storageProviders[storageProvName]; !ok {
					return c.Errf("Unsupported Storage provider '%s'", args[0])
				}
				config.StorageProvider = args[0]
			case "alpn":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return c.ArgErr()
				}
				for _, arg := range args {
					config.ALPN = append(config.ALPN, arg)
				}
			case "must_staple":
				config.MustStaple = true
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
			config.OnDemandState.MaxObtain = int32(maxCertsNum)
		}

		if askURL != "" {
			parsedURL, err := url.Parse(askURL)
			if err != nil {
				return c.Err("ask must be a valid url")
			}

			if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
				return c.Err("ask URL must use http or https")
			}

			config.OnDemandState.AskURL = parsedURL
		}

		// don't try to load certificates unless we're supposed to
		if !config.Enabled || !config.Manual {
			continue
		}

		// load a single certificate and key, if specified
		if certificateFile != "" && keyFile != "" {
			err := config.cacheUnmanagedCertificatePEMFile(certificateFile, keyFile)
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
		err := makeSelfSignedCert(config)
		if err != nil {
			return fmt.Errorf("self-signed: %v", err)
		}
	}

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

			err = cfg.cacheUnmanagedCertificatePEMBytes(certPEMBytes, keyPEMBytes)
			if err != nil {
				return c.Errf("%s: failed to load cert and key for '%s': %v", path, c.Key, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s", path)
		}
		return nil
	})
}
