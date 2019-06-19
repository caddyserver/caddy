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
	"reflect"
	"testing"

	"github.com/klauspost/cpuid"
)

func TestConvertTLSConfigProtocolVersions(t *testing.T) {
	// same min and max protocol versions
	config := &Config{
		Enabled:            true,
		ProtocolMinVersion: tls.VersionTLS12,
		ProtocolMaxVersion: tls.VersionTLS12,
	}
	err := config.buildStandardTLSConfig()
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if got, want := config.tlsConfig.MinVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("Expected min version to be %x, got %x", want, got)
	}
	if got, want := config.tlsConfig.MaxVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("Expected max version to be %x, got %x", want, got)
	}
}

func TestConvertTLSConfigPreferServerCipherSuites(t *testing.T) {
	// prefer server cipher suites
	config := Config{Enabled: true, PreferServerCipherSuites: true}
	err := config.buildStandardTLSConfig()
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if got, want := config.tlsConfig.PreferServerCipherSuites, true; got != want {
		t.Errorf("Expected PreferServerCipherSuites==%v but got %v", want, got)
	}
}

func TestMakeTLSConfigTLSEnabledDisabledError(t *testing.T) {
	// verify handling when Enabled is true and false
	configs := []*Config{
		{Enabled: true},
		{Enabled: false},
	}
	_, err := MakeTLSConfig(configs)
	if err == nil {
		t.Fatalf("Expected an error, but got %v", err)
	}
}

func TestConvertTLSConfigCipherSuites(t *testing.T) {
	// ensure cipher suites are unioned and
	// that TLS_FALLBACK_SCSV is prepended
	configs := []*Config{
		{Enabled: true, Ciphers: []uint16{0xc02c, 0xc030}},
		{Enabled: true, Ciphers: []uint16{0xc012, 0xc030, 0xc00a}},
		{Enabled: true, Ciphers: nil},
	}

	defaultCiphersExpected := getPreferredDefaultCiphers()
	expectedCiphers := [][]uint16{
		{tls.TLS_FALLBACK_SCSV, 0xc02c, 0xc030},
		{tls.TLS_FALLBACK_SCSV, 0xc012, 0xc030, 0xc00a},
		append([]uint16{tls.TLS_FALLBACK_SCSV}, defaultCiphersExpected...),
	}

	for i, config := range configs {
		err := config.buildStandardTLSConfig()
		if err != nil {
			t.Errorf("Test %d: Expected no error, got: %v", i, err)
		}
		if !reflect.DeepEqual(config.tlsConfig.CipherSuites, expectedCiphers[i]) {
			t.Errorf("Test %d: Expected ciphers %v but got %v",
				i, expectedCiphers[i], config.tlsConfig.CipherSuites)
		}

	}
}

func TestGetPreferredDefaultCiphers(t *testing.T) {
	expectedCiphers := defaultCiphers
	if !cpuid.CPU.AesNi() {
		expectedCiphers = defaultCiphersNonAESNI
	}

	// Ensure ordering is correct and ciphers are what we expected.
	result := getPreferredDefaultCiphers()
	for i, actual := range result {
		if actual != expectedCiphers[i] {
			t.Errorf("Expected cipher in position %d to be %0x, got %0x", i, expectedCiphers[i], actual)
		}
	}
}

func TestAssertTLSConfigCompatibleClientCert(t *testing.T) {
	configs := []*Config{
		{Enabled: true, ClientAuth: tls.RequestClientCert, ClientCerts: []string{}},
		{Enabled: true, ClientAuth: tls.RequestClientCert, ClientCerts: []string{"ca_cert.crt"}},
	}

	_, err := MakeTLSConfig(configs)
	if err == nil {
		t.Fatalf("Expected an error, but got %v", err)
	}

	configs = []*Config{
		{Enabled: true, ClientAuth: tls.RequestClientCert, ClientCerts: []string{"ca_cert.crt"}},
		{Enabled: true, ClientAuth: tls.RequestClientCert, ClientCerts: []string{"ca_cert.crt"}},
	}

	_, err = MakeTLSConfig(configs)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
}
