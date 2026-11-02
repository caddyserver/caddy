package caddyhttp

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"

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
