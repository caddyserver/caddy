// Copyright 2015 Matthew Holt and The Caddy Authors
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

	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
)

// CipherSuiteNameSupported returns true if name is
// a supported cipher suite.
func CipherSuiteNameSupported(name string) bool {
	return CipherSuiteID(name) != 0
}

// CipherSuiteID returns the ID of the cipher suite associated with
// the given name, or 0 if the name is not recognized/supported.
func CipherSuiteID(name string) uint16 {
	for _, cs := range SupportedCipherSuites() {
		if cs.Name == name {
			return cs.ID
		}
	}
	return 0
}

// SupportedCipherSuites returns a list of all the cipher suites
// Caddy supports. The list is NOT ordered by security preference.
func SupportedCipherSuites() []*tls.CipherSuite {
	return tls.CipherSuites()
}

// defaultCipherSuites is the ordered list of all the cipher
// suites we want to support by default, assuming AES-NI
// (hardware acceleration for AES).
var defaultCipherSuitesWithAESNI = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// defaultCipherSuites is the ordered list of all the cipher
// suites we want to support by default, assuming lack of
// AES-NI (NO hardware acceleration for AES).
var defaultCipherSuitesWithoutAESNI = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// getOptimalDefaultCipherSuites returns an appropriate cipher
// suite to use depending on the hardware support for AES.
//
// See https://github.com/caddyserver/caddy/issues/1674
func getOptimalDefaultCipherSuites() []uint16 {
	if cpuid.CPU.Supports(cpuid.AESNI) {
		return defaultCipherSuitesWithAESNI
	}
	return defaultCipherSuitesWithoutAESNI
}

// SupportedCurves is the unordered map of supported curves
// or key exchange mechanisms ("curves" traditionally).
// https://golang.org/pkg/crypto/tls/#CurveID
var SupportedCurves = map[string]tls.CurveID{
	"X25519mlkem768": tls.X25519MLKEM768,
	"x25519":         tls.X25519,
	"secp256r1":      tls.CurveP256,
	"secp384r1":      tls.CurveP384,
	"secp521r1":      tls.CurveP521,
}

// supportedCertKeyTypes is all the key types that are supported
// for certificates that are obtained through ACME.
var supportedCertKeyTypes = map[string]certmagic.KeyType{
	"rsa2048": certmagic.RSA2048,
	"rsa4096": certmagic.RSA4096,
	"p256":    certmagic.P256,
	"p384":    certmagic.P384,
	"ed25519": certmagic.ED25519,
}

// defaultCurves is the list of only the curves or key exchange
// mechanisms we want to use by default. The order is irrelevant.
//
// This list should only include mechanisms which are fast by
// design (e.g. X25519) and those for which an optimized assembly
// implementation exists (e.g. P256). The latter ones can be
// found here:
// https://github.com/golang/go/tree/master/src/crypto/elliptic
var defaultCurves = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.X25519,
	tls.CurveP256,
}

// SupportedProtocols is a map of supported protocols.
var SupportedProtocols = map[string]uint16{
	"tls1.2": tls.VersionTLS12,
	"tls1.3": tls.VersionTLS13,
}

// unsupportedProtocols is a map of unsupported protocols.
// Used for logging only, not enforcement.
var unsupportedProtocols = map[string]uint16{
	//nolint:staticcheck
	"ssl3.0": tls.VersionSSL30,
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
}

// publicKeyAlgorithms is the map of supported public key algorithms.
var publicKeyAlgorithms = map[string]x509.PublicKeyAlgorithm{
	"rsa":   x509.RSA,
	"dsa":   x509.DSA,
	"ecdsa": x509.ECDSA,
}

// ProtocolName returns the standard name for the passed protocol version ID
// (e.g.  "TLS1.3") or a fallback representation of the ID value if the version
// is not supported.
func ProtocolName(id uint16) string {
	for k, v := range SupportedProtocols {
		if v == id {
			return k
		}
	}

	for k, v := range unsupportedProtocols {
		if v == id {
			return k
		}
	}

	return fmt.Sprintf("0x%04x", id)
}
