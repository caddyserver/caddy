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

	"github.com/go-acme/lego/certcrypto"
	"github.com/klauspost/cpuid"
)

// supportedCipherSuites is the unordered map of cipher suite
// string names to their definition in crypto/tls. All values
// should be IANA-reserved names. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
// TODO: might not be needed much longer: https://github.com/golang/go/issues/30325
var supportedCipherSuites = map[string]uint16{
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
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
	if cpuid.CPU.AesNi() {
		return defaultCipherSuitesWithAESNI
	}
	return defaultCipherSuitesWithoutAESNI
}

// supportedCurves is the unordered map of supported curves.
// https://golang.org/pkg/crypto/tls/#CurveID
var supportedCurves = map[string]tls.CurveID{
	"X25519": tls.X25519,
	"P256":   tls.CurveP256,
	"P384":   tls.CurveP384,
	"P521":   tls.CurveP521,
}

// supportedCertKeyTypes is all the key types that are supported
// for certificates that are obtained through ACME.
var supportedCertKeyTypes = map[string]certcrypto.KeyType{
	"RSA2048": certcrypto.RSA2048,
	"RSA4096": certcrypto.RSA4096,
	"P256":    certcrypto.EC256,
	"P384":    certcrypto.EC384,
}

// defaultCurves is the list of only the curves we want to use
// by default, in descending order of preference.
//
// This list should only include curves which are fast by design
// (e.g. X25519) and those for which an optimized assembly
// implementation exists (e.g. P256). The latter ones can be
// found here:
// https://github.com/golang/go/tree/master/src/crypto/elliptic
var defaultCurves = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
}

// supportedProtocols is a map of supported protocols.
// HTTP/2 only supports TLS 1.2 and higher.
var supportedProtocols = map[string]uint16{
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
	"tls1.2": tls.VersionTLS12,
	"tls1.3": tls.VersionTLS13,
}

// publicKeyAlgorithms is the map of supported public key algorithms.
var publicKeyAlgorithms = map[string]x509.PublicKeyAlgorithm{
	"rsa":   x509.RSA,
	"dsa":   x509.DSA,
	"ecdsa": x509.ECDSA,
}
