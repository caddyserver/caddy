package caddytls

import (
	"crypto/tls"
	"testing"
)

func TestCipherSuiteNameSupported(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		supported bool
	}{
		{
			name:      "valid TLS 1.2 cipher",
			input:     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			supported: true,
		},
		{
			name:      "valid TLS 1.2 cipher RSA",
			input:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			supported: true,
		},
		{
			name:      "valid ChaCha20 cipher",
			input:     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			supported: true,
		},
		{
			name:      "unknown cipher name",
			input:     "TLS_UNKNOWN_CIPHER",
			supported: false,
		},
		{
			name:      "empty string",
			input:     "",
			supported: false,
		},
		{
			name:      "partial name",
			input:     "TLS_ECDHE",
			supported: false,
		},
		{
			name:      "case sensitive mismatch",
			input:     "tls_ecdhe_ecdsa_with_aes_256_gcm_sha384",
			supported: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CipherSuiteNameSupported(tt.input)
			if got != tt.supported {
				t.Errorf("CipherSuiteNameSupported(%q) = %v, want %v", tt.input, got, tt.supported)
			}
		})
	}
}

func TestCipherSuiteID(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantID uint16
	}{
		{
			name:   "known cipher returns correct ID",
			input:  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			wantID: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		{
			name:   "another known cipher",
			input:  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			wantID: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		{
			name:   "unknown cipher returns 0",
			input:  "DOES_NOT_EXIST",
			wantID: 0,
		},
		{
			name:   "empty string returns 0",
			input:  "",
			wantID: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CipherSuiteID(tt.input)
			if got != tt.wantID {
				t.Errorf("CipherSuiteID(%q) = 0x%04x, want 0x%04x", tt.input, got, tt.wantID)
			}
		})
	}
}

func TestSupportedCipherSuites(t *testing.T) {
	suites := SupportedCipherSuites()
	if len(suites) == 0 {
		t.Fatal("SupportedCipherSuites() returned empty list")
	}

	// Every suite should have a non-empty name and non-zero ID
	for _, cs := range suites {
		if cs.Name == "" {
			t.Errorf("cipher suite with ID 0x%04x has empty name", cs.ID)
		}
		if cs.ID == 0 {
			t.Errorf("cipher suite %q has zero ID", cs.Name)
		}
	}

	// Verify that CipherSuiteID can find each suite by name (round-trip)
	for _, cs := range suites {
		id := CipherSuiteID(cs.Name)
		if id != cs.ID {
			t.Errorf("CipherSuiteID(%q) = 0x%04x, want 0x%04x", cs.Name, id, cs.ID)
		}
	}
}

func TestProtocolName(t *testing.T) {
	tests := []struct {
		name string
		id   uint16
		want string
	}{
		{
			name: "TLS 1.2",
			id:   tls.VersionTLS12,
			want: "tls1.2",
		},
		{
			name: "TLS 1.3",
			id:   tls.VersionTLS13,
			want: "tls1.3",
		},
		{
			name: "unsupported SSL 3.0",
			id:   tls.VersionSSL30, //nolint:staticcheck
			want: "ssl3.0",
		},
		{
			name: "unsupported TLS 1.0",
			id:   tls.VersionTLS10,
			want: "tls1.0",
		},
		{
			name: "unsupported TLS 1.1",
			id:   tls.VersionTLS11,
			want: "tls1.1",
		},
		{
			name: "unknown protocol falls back to hex",
			id:   0x9999,
			want: "0x9999",
		},
		{
			name: "zero protocol falls back to hex",
			id:   0,
			want: "0x0000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProtocolName(tt.id)
			if got != tt.want {
				t.Errorf("ProtocolName(0x%04x) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestSupportedProtocolsMap(t *testing.T) {
	// SupportedProtocols should contain at least TLS 1.2 and 1.3
	expectedProtocols := map[string]uint16{
		"tls1.2": tls.VersionTLS12,
		"tls1.3": tls.VersionTLS13,
	}

	for name, wantID := range expectedProtocols {
		gotID, ok := SupportedProtocols[name]
		if !ok {
			t.Errorf("SupportedProtocols missing %q", name)
			continue
		}
		if gotID != wantID {
			t.Errorf("SupportedProtocols[%q] = 0x%04x, want 0x%04x", name, gotID, wantID)
		}
	}
}

func TestSupportedCurvesMap(t *testing.T) {
	// SupportedCurves should contain key exchanges
	expectedCurves := []string{"x25519", "secp256r1", "secp384r1", "secp521r1"}
	for _, name := range expectedCurves {
		if _, ok := SupportedCurves[name]; !ok {
			t.Errorf("SupportedCurves missing %q", name)
		}
	}

	// All values should be non-zero
	for name, id := range SupportedCurves {
		if id == 0 {
			t.Errorf("SupportedCurves[%q] has zero value", name)
		}
	}
}

func TestGetOptimalDefaultCipherSuites(t *testing.T) {
	suites := getOptimalDefaultCipherSuites()
	if len(suites) == 0 {
		t.Fatal("getOptimalDefaultCipherSuites() returned empty list")
	}

	// All returned IDs should be non-zero
	for i, id := range suites {
		if id == 0 {
			t.Errorf("getOptimalDefaultCipherSuites()[%d] is zero", i)
		}
	}

	// All returned IDs should be recognized cipher suites
	knownSuites := SupportedCipherSuites()
	knownIDs := make(map[uint16]bool)
	for _, cs := range knownSuites {
		knownIDs[cs.ID] = true
	}
	for _, id := range suites {
		if !knownIDs[id] {
			t.Errorf("getOptimalDefaultCipherSuites() contains unrecognized ID 0x%04x", id)
		}
	}
}
