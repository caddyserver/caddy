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

package logging

import (
	"encoding/json"
	"fmt"
	"os"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(JournaldEncoder{})
}

// JournaldEncoder wraps another encoder and prepends a systemd/journald
// priority prefix to each emitted log line. This lets journald classify
// stdout/stderr log lines by severity while leaving the underlying log
// structure to the wrapped encoder.
//
// This encoder does not write directly to journald; it only changes the
// encoded output by adding the priority marker that journald understands.
// The wrapped encoder still controls the actual log format, such as JSON
// or console output.
type JournaldEncoder struct {
	zapcore.Encoder `json:"-"`

	// The underlying encoder that actually encodes the log entries.
	// If not specified, defaults to "json", unless the output is a
	// terminal, in which case it defaults to "console".
	WrappedRaw json.RawMessage `json:"wrap,omitempty" caddy:"namespace=caddy.logging.encoders inline_key=format"`

	wrappedIsDefault bool
	ctx              caddy.Context
}

// CaddyModule returns the Caddy module information.
func (JournaldEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.journald",
		New: func() caddy.Module { return new(JournaldEncoder) },
	}
}

// Provision sets up the encoder.
func (je *JournaldEncoder) Provision(ctx caddy.Context) error {
	je.ctx = ctx

	if je.WrappedRaw == nil {
		je.Encoder = &JSONEncoder{}
		if p, ok := je.Encoder.(caddy.Provisioner); ok {
			if err := p.Provision(ctx); err != nil {
				return fmt.Errorf("provisioning fallback encoder module: %v", err)
			}
		}
		je.wrappedIsDefault = true
	} else {
		val, err := ctx.LoadModule(je, "WrappedRaw")
		if err != nil {
			return fmt.Errorf("loading wrapped encoder module: %v", err)
		}
		je.Encoder = val.(zapcore.Encoder)
	}

	suppressEncoderTimestamp(je.Encoder)

	return nil
}

// ConfigureDefaultFormat will set the default wrapped format to "console"
// if the writer is a terminal. If already configured, it passes through
// the writer so a deeply nested encoder can configure its own default format.
func (je *JournaldEncoder) ConfigureDefaultFormat(wo caddy.WriterOpener) error {
	if !je.wrappedIsDefault {
		if cfd, ok := je.Encoder.(caddy.ConfiguresFormatterDefault); ok {
			return cfd.ConfigureDefaultFormat(wo)
		}
		return nil
	}

	if caddy.IsWriterStandardStream(wo) && term.IsTerminal(int(os.Stderr.Fd())) {
		je.Encoder = &ConsoleEncoder{}
		if p, ok := je.Encoder.(caddy.Provisioner); ok {
			if err := p.Provision(je.ctx); err != nil {
				return fmt.Errorf("provisioning fallback encoder module: %v", err)
			}
		}
	}

	suppressEncoderTimestamp(je.Encoder)

	return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	journald {
//	    wrap <another encoder>
//	}
//
// Example:
//
//	log {
//	    format journald {
//	        wrap json
//	    }
//	}
func (je *JournaldEncoder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume encoder name
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		if d.Val() != "wrap" {
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
		if !d.NextArg() {
			return d.ArgErr()
		}
		moduleName := d.Val()
		moduleID := "caddy.logging.encoders." + moduleName
		unm, err := caddyfile.UnmarshalModule(d, moduleID)
		if err != nil {
			return err
		}
		enc, ok := unm.(zapcore.Encoder)
		if !ok {
			return d.Errf("module %s (%T) is not a zapcore.Encoder", moduleID, unm)
		}
		je.WrappedRaw = caddyconfig.JSONModuleObject(enc, "format", moduleName, nil)
	}

	return nil
}

// Clone implements zapcore.Encoder.
func (je JournaldEncoder) Clone() zapcore.Encoder {
	return JournaldEncoder{
		Encoder: je.Encoder.Clone(),
	}
}

// EncodeEntry implements zapcore.Encoder.
func (je JournaldEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	encoded, err := je.Encoder.Clone().EncodeEntry(ent, fields)
	if err != nil {
		return nil, err
	}

	out := bufferpool.Get()
	out.AppendString(journaldPriorityPrefix(ent.Level))
	out.AppendBytes(encoded.Bytes())
	encoded.Free()

	return out, nil
}

func journaldPriorityPrefix(level zapcore.Level) string {
	switch level {
	case zapcore.InvalidLevel:
		return "<6>"
	case zapcore.DebugLevel:
		return "<7>"
	case zapcore.InfoLevel:
		return "<6>"
	case zapcore.WarnLevel:
		return "<4>"
	case zapcore.ErrorLevel:
		return "<3>"
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		return "<2>"
	default:
		return "<6>"
	}
}

func suppressEncoderTimestamp(enc zapcore.Encoder) {
	empty := ""

	switch e := enc.(type) {
	case *ConsoleEncoder:
		e.TimeKey = &empty
		_ = e.Provision(caddy.Context{})
	case *JSONEncoder:
		e.TimeKey = &empty
		_ = e.Provision(caddy.Context{})
	case *AppendEncoder:
		suppressEncoderTimestamp(e.wrapped)
	case *FilterEncoder:
		suppressEncoderTimestamp(e.wrapped)
	case *JournaldEncoder:
		suppressEncoderTimestamp(e.Encoder)
	}
}

// Interface guards
var (
	_ zapcore.Encoder                  = (*JournaldEncoder)(nil)
	_ caddyfile.Unmarshaler            = (*JournaldEncoder)(nil)
	_ caddy.ConfiguresFormatterDefault = (*JournaldEncoder)(nil)
)
