package internal

import (
	"net/http"
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestLoggableHTTPHeaderRedactsSensitive(t *testing.T) {
	h := http.Header{
		"Authorization":       []string{"Bearer secret-token"},
		"Proxy-Authorization": []string{"Basic dXNlcjpwYXNz"},
		"Cookie":              []string{"session=abc"},
		"Set-Cookie":          []string{"session=abc; Path=/"},
		"X-Custom":            []string{"keep-me"},
	}

	enc := zapcore.NewMapObjectEncoder()
	if err := (LoggableHTTPHeader{Header: h}).MarshalLogObject(enc); err != nil {
		t.Fatalf("MarshalLogObject: %v", err)
	}

	for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"} {
		if got := singleStringField(t, enc, key); got != "REDACTED" {
			t.Errorf("%s: expected REDACTED, got %q", key, got)
		}
	}

	if got := singleStringField(t, enc, "X-Custom"); got != "keep-me" {
		t.Errorf("X-Custom: expected keep-me, got %q", got)
	}
}

func singleStringField(t *testing.T, enc *zapcore.MapObjectEncoder, key string) string {
	t.Helper()
	raw, ok := enc.Fields[key]
	if !ok {
		t.Fatalf("%s: field missing", key)
	}
	arr, ok := raw.([]any)
	if !ok {
		t.Fatalf("%s: expected []any, got %T", key, raw)
	}
	if len(arr) != 1 {
		t.Fatalf("%s: expected 1 element, got %d", key, len(arr))
	}
	s, ok := arr[0].(string)
	if !ok {
		t.Fatalf("%s: expected string, got %T", key, arr[0])
	}
	return s
}

func TestLoggableHTTPHeaderLogsCredentialsWhenEnabled(t *testing.T) {
	h := http.Header{"Authorization": []string{"Bearer secret-token"}}

	enc := zapcore.NewMapObjectEncoder()
	err := LoggableHTTPHeader{Header: h, ShouldLogCredentials: true}.MarshalLogObject(enc)
	if err != nil {
		t.Fatalf("MarshalLogObject: %v", err)
	}

	if got := singleStringField(t, enc, "Authorization"); got != "Bearer secret-token" {
		t.Errorf("expected credentials to be logged verbatim, got %q", got)
	}
}

func TestLoggableHTTPHeaderNilHeaderIsNoOp(t *testing.T) {
	enc := zapcore.NewMapObjectEncoder()
	if err := (LoggableHTTPHeader{}).MarshalLogObject(enc); err != nil {
		t.Fatalf("MarshalLogObject: %v", err)
	}
	if len(enc.Fields) != 0 {
		t.Errorf("expected no fields, got %v", enc.Fields)
	}
}

func TestLoggableHTTPHeaderRedactsIsCaseInsensitive(t *testing.T) {
	h := http.Header{"authorization": []string{"Bearer secret"}}

	enc := zapcore.NewMapObjectEncoder()
	if err := (LoggableHTTPHeader{Header: h}).MarshalLogObject(enc); err != nil {
		t.Fatalf("MarshalLogObject: %v", err)
	}

	if got := singleStringField(t, enc, "authorization"); got != "REDACTED" {
		t.Errorf("expected lowercase authorization to be redacted, got %q", got)
	}
}
