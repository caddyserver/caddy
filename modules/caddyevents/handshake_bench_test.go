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

package caddyevents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func benchCert(tb testing.TB) tls.Certificate {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// benchmarkCertLookup measures CertMagic's GetCertificate, which Caddy calls
// once per TLS handshake. CertMagic emits "tls_get_certificate" there, so this
// shows what the events app costs a handshake when nothing is subscribed.
func benchmarkCertLookup(b *testing.B, onEvent func(context.Context, string, map[string]any) error) {
	b.Helper()

	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil },
		Logger:           zap.NewNop(),
	})
	b.Cleanup(cache.Stop)

	cfg = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: b.TempDir()},
		Logger:  zap.NewNop(),
		OnEvent: onEvent,
	})
	if _, err := cfg.CacheUnmanagedTLSCertificate(context.Background(), benchCert(b), nil); err != nil {
		b.Fatal(err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName:        "example.com",
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	}
	if _, err := cfg.GetCertificate(hello); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cfg.GetCertificate(hello); err != nil {
			b.Fatal(err)
		}
	}
}

// Caddy always binds the TLS app to the events app, so this is what a
// handshake pays for the tls_get_certificate event in a config that has no
// subscriptions at all -- which is every config that does not use the events
// app. The hook body is what (*caddytls.TLS).onEvent does.
func BenchmarkCertLookupWithEventsApp(b *testing.B) {
	app, ctx, cancel := testApp(b)
	defer cancel()

	benchmarkCertLookup(b, func(_ context.Context, name string, data map[string]any) error {
		return app.Emit(ctx, name, data).Aborted
	})
}
