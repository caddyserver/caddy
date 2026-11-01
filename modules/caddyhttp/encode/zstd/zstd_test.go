package caddyzstd

import (
	"bytes"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestZstdCaddyModule(t *testing.T) {
	z := Zstd{}
	info := z.CaddyModule()
	if info.ID != "http.encoders.zstd" {
		t.Errorf("CaddyModule().ID = %v, want 'http.encoders.zstd'", info.ID)
	}
	if info.New == nil {
		t.Fatal("CaddyModule().New is nil")
	}
	mod := info.New()
	if _, ok := mod.(*Zstd); !ok {
		t.Errorf("CaddyModule().New() returned %T, want *Zstd", mod)
	}
}

func TestZstdAcceptEncoding(t *testing.T) {
	z := Zstd{}
	if got := z.AcceptEncoding(); got != "zstd" {
		t.Errorf("AcceptEncoding() = %q, want %q", got, "zstd")
	}
}

func TestZstdProvision(t *testing.T) {
	tests := []struct {
		name      string
		level     string
		wantErr   bool
		wantLevel zstd.EncoderLevel
	}{
		{
			name:      "empty defaults to SpeedDefault",
			level:     "",
			wantLevel: zstd.SpeedDefault,
		},
		{
			name:      "fastest",
			level:     zstd.SpeedFastest.String(),
			wantLevel: zstd.SpeedFastest,
		},
		{
			name:      "default",
			level:     zstd.SpeedDefault.String(),
			wantLevel: zstd.SpeedDefault,
		},
		{
			name:      "better",
			level:     zstd.SpeedBetterCompression.String(),
			wantLevel: zstd.SpeedBetterCompression,
		},
		{
			name:      "best",
			level:     zstd.SpeedBestCompression.String(),
			wantLevel: zstd.SpeedBestCompression,
		},
		{
			name:    "invalid level",
			level:   "superfast",
			wantErr: true,
		},
		{
			name:    "numeric level string",
			level:   "5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := &Zstd{Level: tt.level}
			err := z.Provision(caddy.Context{})
			if tt.wantErr {
				if err == nil {
					t.Error("Provision() should return error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Provision() error: %v", err)
			}
			if z.level != tt.wantLevel {
				t.Errorf("level = %v, want %v", z.level, tt.wantLevel)
			}
		})
	}
}

func TestZstdNewEncoder(t *testing.T) {
	z := Zstd{level: zstd.SpeedFastest}
	enc := z.NewEncoder()
	if enc == nil {
		t.Fatal("NewEncoder() returned nil")
	}

	// Verify the encoder can actually compress data
	var buf bytes.Buffer
	enc.Reset(&buf)
	data := []byte("Hello, Zstandard compression test! This is some test data to compress.")
	_, err := enc.Write(data)
	if err != nil {
		t.Fatalf("encoder.Write() error: %v", err)
	}
	err = enc.Close()
	if err != nil {
		t.Fatalf("encoder.Close() error: %v", err)
	}

	// Verify we can decompress the output
	reader, err := zstd.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("zstd.NewReader() error: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("io.ReadAll() error: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("round-trip mismatch: got %q, want %q", decoded, data)
	}
}

func TestZstdUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLevel string
		wantErr   bool
	}{
		{
			name:      "with fastest level",
			input:     "zstd fastest",
			wantLevel: "fastest",
		},
		{
			name:      "with default level",
			input:     "zstd default",
			wantLevel: "default",
		},
		{
			name:      "with better level",
			input:     "zstd better",
			wantLevel: "better",
		},
		{
			name:      "with best level",
			input:     "zstd best",
			wantLevel: "best",
		},
		{
			name:      "no level keeps empty",
			input:     "zstd",
			wantLevel: "",
		},
		{
			name:    "invalid level",
			input:   "zstd invalid_level",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			z := &Zstd{}
			err := z.UnmarshalCaddyfile(d)
			if tt.wantErr {
				if err == nil {
					t.Error("UnmarshalCaddyfile() should return error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalCaddyfile() error: %v", err)
			}
			if z.Level != tt.wantLevel {
				t.Errorf("Level = %q, want %q", z.Level, tt.wantLevel)
			}
		})
	}
}
