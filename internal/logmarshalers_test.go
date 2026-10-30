package internal

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
)

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
