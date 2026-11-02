package caddygzip

import (
	"bytes"
	"io"
	"strconv"
	"testing"

	"github.com/klauspost/compress/gzip"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestGzipCaddyModule(t *testing.T) {
	g := Gzip{}
	info := g.CaddyModule()
	if info.ID != "http.encoders.gzip" {
		t.Errorf("CaddyModule().ID = %v, want 'http.encoders.gzip'", info.ID)
	}
	if info.New == nil {
		t.Fatal("CaddyModule().New is nil")
	}
	mod := info.New()
	if _, ok := mod.(*Gzip); !ok {
		t.Errorf("CaddyModule().New() returned %T, want *Gzip", mod)
	}
}

func TestGzipAcceptEncoding(t *testing.T) {
	g := Gzip{}
	if got := g.AcceptEncoding(); got != "gzip" {
		t.Errorf("AcceptEncoding() = %q, want %q", got, "gzip")
	}
}

func TestGzipValidate(t *testing.T) {
	tests := []struct {
		name    string
		level   int
		wantErr bool
	}{
		{name: "default level 5", level: 5},
		{name: "best speed", level: gzip.BestSpeed},
		{name: "best compression", level: gzip.BestCompression},
		{name: "no compression", level: gzip.NoCompression},
		{name: "stateless compression", level: gzip.StatelessCompression},
		{name: "too low", level: gzip.StatelessCompression - 1, wantErr: true},
		{name: "too high", level: 10, wantErr: true},
		{name: "way too high", level: 100, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := Gzip{Level: tt.level}
			err := g.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("Validate() with level %d should return error", tt.level)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() with level %d unexpected error: %v", tt.level, err)
			}
		})
	}
}

func TestGzipNewEncoder(t *testing.T) {
	g := Gzip{Level: gzip.BestSpeed}
	enc := g.NewEncoder()
	if enc == nil {
		t.Fatal("NewEncoder() returned nil")
	}

	// Verify the encoder can actually compress data
	var buf bytes.Buffer
	enc.Reset(&buf)
	data := []byte("Hello, Gzip compression test!")
	_, err := enc.Write(data)
	if err != nil {
		t.Fatalf("encoder.Write() error: %v", err)
	}
	err = enc.Close()
	if err != nil {
		t.Fatalf("encoder.Close() error: %v", err)
	}

	// Verify we can decompress the output
	reader, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatalf("gzip.NewReader() error: %v", err)
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

func TestGzipUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLevel int
		wantErr   bool
	}{
		{
			name:      "with level",
			input:     "gzip 6",
			wantLevel: 6,
		},
		{
			name:      "no level keeps zero",
			input:     "gzip",
			wantLevel: 0,
		},
		{
			name:    "invalid level",
			input:   "gzip notanumber",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			g := &Gzip{}
			err := g.UnmarshalCaddyfile(d)
			if tt.wantErr {
				if err == nil {
					t.Error("UnmarshalCaddyfile() should return error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalCaddyfile() error: %v", err)
			}
			if g.Level != tt.wantLevel {
				t.Errorf("Level = %d, want %d", g.Level, tt.wantLevel)
			}
		})
	}
}

func TestGzipNewEncoderAllLevels(t *testing.T) {
	// Verify NewEncoder works at all valid compression levels
	for level := gzip.StatelessCompression; level <= gzip.BestCompression; level++ {
		t.Run("level_"+strconv.Itoa(level), func(t *testing.T) {
			g := Gzip{Level: level}
			enc := g.NewEncoder()
			if enc == nil {
				t.Fatalf("NewEncoder() at level %d returned nil", level)
			}
		})
	}
}
