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
	"fmt"
	"strings"

	"github.com/mholt/caddy/telemetry"
	"github.com/mholt/certmagic"
)

// configGroup is a type that keys configs by their hostname
// (hostnames can have wildcard characters; use the getConfig
// method to get a config by matching its hostname).
type configGroup map[string]*Config

// getConfig gets the config by the first key match for hello.
// In other words, "sub.foo.bar" will get the config for "*.foo.bar"
// if that is the closest match. If no match is found, the first
// (random) config will be loaded, which will defer any TLS alerts
// to the certificate validation (this may or may not be ideal;
// let's talk about it if this becomes problematic).
//
// This function follows nearly the same logic to lookup
// a hostname as the getCertificate function uses.
func (cg configGroup) getConfig(hello *tls.ClientHelloInfo) *Config {
	name := certmagic.CertNameFromClientHello(hello)

	// exact match? great, let's use it
	if config, ok := cg[name]; ok {
		return config
	}

	// try replacing labels in the name with wildcards until we get a match
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if config, ok := cg[candidate]; ok {
			return config
		}
	}

	// try a config that serves all names (the above
	// loop doesn't try empty string; for hosts defined
	// with only a port, for instance, like ":443") -
	// also known as the default config
	if config, ok := cg[""]; ok {
		return config
	}

	return nil
}

// GetConfigForClient gets a TLS configuration satisfying clientHello.
// In getting the configuration, it abides the rules and settings
// defined in the Config that matches clientHello.ServerName. If no
// tls.Config is set on the matching Config, a nil value is returned.
//
// This method is safe for use as a tls.Config.GetConfigForClient callback.
func (cg configGroup) GetConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	config := cg.getConfig(clientHello)
	if config != nil {
		return config.tlsConfig, nil
	}
	return nil, nil
}

// ClientHelloInfo is our own version of the standard lib's
// tls.ClientHelloInfo. As of May 2018, any fields populated
// by the Go standard library are not guaranteed to have their
// values in the original order as on the wire.
type ClientHelloInfo struct {
	Version            uint16        `json:"version,omitempty"`
	CipherSuites       []uint16      `json:"cipher_suites,omitempty"`
	Extensions         []uint16      `json:"extensions,omitempty"`
	CompressionMethods []byte        `json:"compression,omitempty"`
	Curves             []tls.CurveID `json:"curves,omitempty"`
	Points             []uint8       `json:"points,omitempty"`

	// Whether a couple of fields are unknown; if not, the key will encode
	// differently to reflect that, as opposed to being known empty values.
	// (some fields may be unknown depending on what package is being used;
	// i.e. the Go standard lib doesn't expose some things)
	// (very important to NOT encode these to JSON)
	ExtensionsUnknown         bool `json:"-"`
	CompressionMethodsUnknown bool `json:"-"`
}

// Key returns a standardized string form of the data in info,
// useful for identifying duplicates.
func (info ClientHelloInfo) Key() string {
	extensions, compressionMethods := "?", "?"
	if !info.ExtensionsUnknown {
		extensions = fmt.Sprintf("%x", info.Extensions)
	}
	if !info.CompressionMethodsUnknown {
		compressionMethods = fmt.Sprintf("%x", info.CompressionMethods)
	}
	return telemetry.FastHash([]byte(fmt.Sprintf("%x-%x-%s-%s-%x-%x",
		info.Version, info.CipherSuites, extensions,
		compressionMethods, info.Curves, info.Points)))
}

// ClientHelloTelemetry determines whether to report
// TLS ClientHellos to telemetry. Disable if doing
// it from a different package.
var ClientHelloTelemetry = true
