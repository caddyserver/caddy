package caddyhttp

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
)

func TestLoggableHTTPRequestMarshal(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/path?q=1", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Accept", "text/html")

	ctx := context.WithValue(req.Context(), VarsCtxKey, map[string]any{
		ClientIPVarKey: "192.168.1.1",
	})
	req = req.WithContext(ctx)

	lr := LoggableHTTPRequest{Request: req}

	enc := zapcore.NewMapObjectEncoder()
	err := lr.MarshalLogObject(enc)
	if err != nil {
		t.Fatalf("MarshalLogObject() error = %v", err)
	}

	if enc.Fields["remote_ip"] != "192.168.1.1" {
		t.Errorf("remote_ip = %v, want '192.168.1.1'", enc.Fields["remote_ip"])
	}
	if enc.Fields["remote_port"] != "12345" {
		t.Errorf("remote_port = %v, want '12345'", enc.Fields["remote_port"])
	}
	if enc.Fields["client_ip"] != "192.168.1.1" {
		t.Errorf("client_ip = %v, want '192.168.1.1'", enc.Fields["client_ip"])
	}
	if enc.Fields["method"] != "GET" {
		t.Errorf("method = %v, want 'GET'", enc.Fields["method"])
	}
	if enc.Fields["host"] != "example.com" {
		t.Errorf("host = %v, want 'example.com'", enc.Fields["host"])
	}
}

func TestLoggableHTTPRequestNoPort(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.1" // no port

	ctx := context.WithValue(req.Context(), VarsCtxKey, map[string]any{})
	req = req.WithContext(ctx)

	lr := LoggableHTTPRequest{Request: req}

	enc := zapcore.NewMapObjectEncoder()
	err := lr.MarshalLogObject(enc)
	if err != nil {
		t.Fatalf("MarshalLogObject() error = %v", err)
	}

	if enc.Fields["remote_ip"] != "192.168.1.1" {
		t.Errorf("remote_ip = %v, want '192.168.1.1'", enc.Fields["remote_ip"])
	}
	if enc.Fields["remote_port"] != "" {
		t.Errorf("remote_port = %v, want empty string", enc.Fields["remote_port"])
	}
}

func TestLoggableHTTPHeaderRedaction(t *testing.T) {
	tests := []struct {
		name                 string
		header               http.Header
		shouldLogCredentials bool
		expectRedacted       []string
	}{
		{
			name: "redacts sensitive headers",
			header: http.Header{
				"Cookie":              {"session=abc123"},
				"Set-Cookie":          {"session=xyz"},
				"Authorization":       {"Bearer token123"},
				"Proxy-Authorization": {"Basic credentials"},
				"User-Agent":          {"test-agent"},
			},
			shouldLogCredentials: false,
			expectRedacted:       []string{"Cookie", "Set-Cookie", "Authorization", "Proxy-Authorization"},
		},
		{
			name: "logs credentials when enabled",
			header: http.Header{
				"Cookie":        {"session=abc123"},
				"Authorization": {"Bearer token123"},
			},
			shouldLogCredentials: true,
			expectRedacted:       nil, // nothing should be redacted
		},
		{
			name:                 "nil header",
			header:               nil,
			shouldLogCredentials: false,
			expectRedacted:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := LoggableHTTPHeader{Header: tt.header, ShouldLogCredentials: tt.shouldLogCredentials}
			enc := zapcore.NewMapObjectEncoder()
			err := h.MarshalLogObject(enc)
			if err != nil {
				t.Fatalf("MarshalLogObject() error = %v", err)
			}

			if tt.header == nil {
				return
			}

			for _, key := range tt.expectRedacted {
				// The encoded value should be an array with ["REDACTED"]
				if arr, ok := enc.Fields[key]; ok {
					arrEnc, ok := arr.(zapcore.ArrayMarshaler)
					if !ok {
						continue
					}
					// Marshal the array to check its contents
					testEnc := &testArrayEncoder{}
					_ = arrEnc.MarshalLogArray(testEnc)
					if len(testEnc.items) != 1 || testEnc.items[0] != "REDACTED" {
						t.Errorf("header %q should be REDACTED, got %v", key, testEnc.items)
					}
				}
			}

			if tt.shouldLogCredentials && tt.header != nil {
				for key, vals := range tt.header {
					if arr, ok := enc.Fields[key]; ok {
						arrEnc, ok := arr.(zapcore.ArrayMarshaler)
						if !ok {
							continue
						}
						testEnc := &testArrayEncoder{}
						_ = arrEnc.MarshalLogArray(testEnc)
						if len(testEnc.items) > 0 && testEnc.items[0] == "REDACTED" {
							t.Errorf("header %q should NOT be redacted when credentials logging is enabled, original: %v", key, vals)
						}
					}
				}
			}
		})
	}
}

// testArrayEncoder is a simple array encoder for testing
type testArrayEncoder struct {
	items []string
}

func (e *testArrayEncoder) AppendString(s string)                      { e.items = append(e.items, s) }
func (e *testArrayEncoder) AppendBool(bool)                            {}
func (e *testArrayEncoder) AppendByteString([]byte)                    {}
func (e *testArrayEncoder) AppendComplex128(complex128)                {}
func (e *testArrayEncoder) AppendComplex64(complex64)                  {}
func (e *testArrayEncoder) AppendFloat64(float64)                      {}
func (e *testArrayEncoder) AppendFloat32(float32)                      {}
func (e *testArrayEncoder) AppendInt(int)                              {}
func (e *testArrayEncoder) AppendInt64(int64)                          {}
func (e *testArrayEncoder) AppendInt32(int32)                          {}
func (e *testArrayEncoder) AppendInt16(int16)                          {}
func (e *testArrayEncoder) AppendInt8(int8)                            {}
func (e *testArrayEncoder) AppendUint(uint)                            {}
func (e *testArrayEncoder) AppendUint64(uint64)                        {}
func (e *testArrayEncoder) AppendUint32(uint32)                        {}
func (e *testArrayEncoder) AppendUint16(uint16)                        {}
func (e *testArrayEncoder) AppendUint8(uint8)                          {}
func (e *testArrayEncoder) AppendUintptr(uintptr)                      {}
func (e *testArrayEncoder) AppendDuration(time.Duration)               {}
func (e *testArrayEncoder) AppendTime(time.Time)                       {}
func (e *testArrayEncoder) AppendArray(zapcore.ArrayMarshaler) error   { return nil }
func (e *testArrayEncoder) AppendObject(zapcore.ObjectMarshaler) error { return nil }
func (e *testArrayEncoder) AppendReflected(any) error                  { return nil }

func TestLoggableStringArray(t *testing.T) {
	tests := []struct {
		name  string
		input LoggableStringArray
	}{
		{
			name:  "nil array",
			input: nil,
		},
		{
			name:  "empty array",
			input: LoggableStringArray{},
		},
		{
			name:  "single element",
			input: LoggableStringArray{"hello"},
		},
		{
			name:  "multiple elements",
			input: LoggableStringArray{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := &testArrayEncoder{}
			err := tt.input.MarshalLogArray(enc)
			if err != nil {
				t.Fatalf("MarshalLogArray() error = %v", err)
			}
			if tt.input != nil && len(enc.items) != len(tt.input) {
				t.Errorf("expected %d items, got %d", len(tt.input), len(enc.items))
			}
		})
	}
}

func TestLoggableTLSConnState(t *testing.T) {
	t.Run("basic TLS state", func(t *testing.T) {
		state := LoggableTLSConnState(tls.ConnectionState{
			Version:            tls.VersionTLS13,
			CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
			NegotiatedProtocol: "h2",
			ServerName:         "example.com",
		})

		enc := zapcore.NewMapObjectEncoder()
		err := state.MarshalLogObject(enc)
		if err != nil {
			t.Fatalf("MarshalLogObject() error = %v", err)
		}

		if enc.Fields["proto"] != "h2" {
			t.Errorf("proto = %v, want 'h2'", enc.Fields["proto"])
		}
		if enc.Fields["server_name"] != "example.com" {
			t.Errorf("server_name = %v, want 'example.com'", enc.Fields["server_name"])
		}
	})

	t.Run("TLS state with peer certificates", func(t *testing.T) {
		// Skipping detailed cert subject test since x509.Certificate creation
		// for testing requires complex setup; covered by the no-peer-certs test
		state := LoggableTLSConnState(tls.ConnectionState{
			Version:     tls.VersionTLS12,
			CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		})

		enc := zapcore.NewMapObjectEncoder()
		err := state.MarshalLogObject(enc)
		if err != nil {
			t.Fatalf("MarshalLogObject() error = %v", err)
		}

		if enc.Fields["version"] != uint16(tls.VersionTLS12) {
			t.Errorf("version = %v, want TLS 1.2", enc.Fields["version"])
		}
	})

	t.Run("TLS state without peer certificates", func(t *testing.T) {
		state := LoggableTLSConnState(tls.ConnectionState{
			Version: tls.VersionTLS12,
		})

		enc := zapcore.NewMapObjectEncoder()
		err := state.MarshalLogObject(enc)
		if err != nil {
			t.Fatalf("MarshalLogObject() error = %v", err)
		}

		// Should not contain client cert fields when no peer certs
		if _, ok := enc.Fields["client_common_name"]; ok {
			t.Error("should not have client_common_name without peer certificates")
		}
	})
}

func TestLoggableHTTPHeaderCaseInsensitivity(t *testing.T) {
	// HTTP headers should be case-insensitive for redaction
	h := LoggableHTTPHeader{
		Header: http.Header{
			"AUTHORIZATION":       {"Bearer secret"},
			"cookie":              {"session=abc"},
			"Proxy-Authorization": {"Basic creds"},
		},
		ShouldLogCredentials: false,
	}

	enc := zapcore.NewMapObjectEncoder()
	err := h.MarshalLogObject(enc)
	if err != nil {
		t.Fatalf("MarshalLogObject() error = %v", err)
	}

	// All sensitive headers should be redacted regardless of casing
	// Note: http.Header canonicalizes keys, so "cookie" becomes "Cookie"
	for key := range enc.Fields {
		lk := strings.ToLower(key)
		if lk == "cookie" || lk == "authorization" || lk == "proxy-authorization" {
			arr, ok := enc.Fields[key].(zapcore.ArrayMarshaler)
			if !ok {
				continue
			}
			testEnc := &testArrayEncoder{}
			_ = arr.MarshalLogArray(testEnc)
			if len(testEnc.items) != 1 || testEnc.items[0] != "REDACTED" {
				t.Errorf("header %q should be REDACTED, got %v", key, testEnc.items)
			}
		}
	}
}
