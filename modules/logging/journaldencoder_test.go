package logging

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestJournaldPriorityPrefix(t *testing.T) {
	tests := []struct {
		level zapcore.Level
		want  string
	}{
		{level: zapcore.InvalidLevel, want: "<6>"},
		{level: zapcore.DebugLevel, want: "<7>"},
		{level: zapcore.InfoLevel, want: "<6>"},
		{level: zapcore.WarnLevel, want: "<4>"},
		{level: zapcore.ErrorLevel, want: "<3>"},
		{level: zapcore.DPanicLevel, want: "<2>"},
		{level: zapcore.PanicLevel, want: "<2>"},
		{level: zapcore.FatalLevel, want: "<2>"},
	}

	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			if got := journaldPriorityPrefix(tt.level); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestJournaldEncoderEncodeEntry(t *testing.T) {
	tests := []struct {
		name  string
		level zapcore.Level
		want  string
	}{
		{name: "debug", level: zapcore.DebugLevel, want: "<7>wrapped\n"},
		{name: "info", level: zapcore.InfoLevel, want: "<6>wrapped\n"},
		{name: "warn", level: zapcore.WarnLevel, want: "<4>wrapped\n"},
		{name: "error", level: zapcore.ErrorLevel, want: "<3>wrapped\n"},
		{name: "panic", level: zapcore.PanicLevel, want: "<2>wrapped\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := JournaldEncoder{Encoder: staticEncoder{output: "wrapped\n"}}
			buf, err := enc.EncodeEntry(zapcore.Entry{Level: tt.level}, nil)
			if err != nil {
				t.Fatalf("EncodeEntry() error = %v", err)
			}
			defer buf.Free()

			if got := buf.String(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJournaldEncoderUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
journald {
	wrap console
}
`)

	var enc JournaldEncoder
	if err := enc.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(enc.WrappedRaw, &got); err != nil {
		t.Fatalf("unmarshal wrapped encoder: %v", err)
	}

	if got["format"] != "console" {
		t.Fatalf("wrapped format = %v, want console", got["format"])
	}
}

func TestJournaldEncoderPreservesJSONTimestamp(t *testing.T) {
	enc := &JournaldEncoder{
		Encoder: &JSONEncoder{},
	}
	if err := enc.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	buf, err := enc.EncodeEntry(zapcore.Entry{
		Level:   zapcore.InfoLevel,
		Time:    fixedEntryTime(),
		Message: "hello",
	}, nil)
	if err != nil {
		t.Fatalf("EncodeEntry() error = %v", err)
	}
	defer buf.Free()

	got := buf.String()
	if !strings.Contains(got, `"ts"`) {
		t.Fatalf("got JSON output without ts field: %q", got)
	}
}

func TestJournaldEncoderSuppressesConsoleTimestamp(t *testing.T) {
	enc := &JournaldEncoder{
		Encoder: &ConsoleEncoder{},
	}
	if err := enc.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	buf, err := enc.EncodeEntry(zapcore.Entry{
		Level:   zapcore.InfoLevel,
		Time:    fixedEntryTime(),
		Message: "hello",
	}, nil)
	if err != nil {
		t.Fatalf("EncodeEntry() error = %v", err)
	}
	defer buf.Free()

	got := buf.String()
	if strings.Contains(got, "2001/02/03") {
		t.Fatalf("got console output with timestamp: %q", got)
	}
}

type staticEncoder struct {
	nopEncoder
	output string
}

func (se staticEncoder) Clone() zapcore.Encoder { return se }

func (se staticEncoder) EncodeEntry(zapcore.Entry, []zapcore.Field) (*buffer.Buffer, error) {
	buf := bufferpool.Get()
	buf.AppendString(se.output)
	return buf, nil
}

func fixedEntryTime() (ts time.Time) {
	return time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
}
