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
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(AppendEncoder{})
}

// AppendEncoder can be used to add fields to all log entries
// that pass through it. It is a wrapper around another
// encoder, which it uses to actually encode the log entries.
// It is most useful for adding information about the Caddy
// instance that is producing the log entries, possibly via
// an environment variable.
type AppendEncoder struct {
	// The underlying encoder that actually encodes the
	// log entries. If not specified, defaults to "json",
	// unless the output is a terminal, in which case
	// it defaults to "console".
	WrappedRaw json.RawMessage `json:"wrap,omitempty" caddy:"namespace=caddy.logging.encoders inline_key=format"`

	// A map of field names to their values. The values
	// can be global placeholders (e.g. env vars), or constants.
	// Note that the encoder does not run as part of an HTTP
	// request context, so request placeholders are not available.
	Fields map[string]any `json:"fields,omitempty"`

	wrapped zapcore.Encoder
	repl    *caddy.Replacer

	wrappedIsDefault bool
	ctx              caddy.Context
}

// CaddyModule returns the Caddy module information.
func (AppendEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.append",
		New: func() caddy.Module { return new(AppendEncoder) },
	}
}

// Provision sets up the encoder.
func (fe *AppendEncoder) Provision(ctx caddy.Context) error {
	fe.ctx = ctx
	fe.repl = caddy.NewReplacer()

	if fe.WrappedRaw == nil {
		// if wrap is not specified, default to JSON
		fe.wrapped = &JSONEncoder{}
		if p, ok := fe.wrapped.(caddy.Provisioner); ok {
			if err := p.Provision(ctx); err != nil {
				return fmt.Errorf("provisioning fallback encoder module: %v", err)
			}
		}
		fe.wrappedIsDefault = true
	} else {
		// set up wrapped encoder
		val, err := ctx.LoadModule(fe, "WrappedRaw")
		if err != nil {
			return fmt.Errorf("loading fallback encoder module: %v", err)
		}
		fe.wrapped = val.(zapcore.Encoder)
	}

	return nil
}

// ConfigureDefaultFormat will set the default format to "console"
// if the writer is a terminal. If already configured, it passes
// through the writer so a deeply nested encoder can configure
// its own default format.
func (fe *AppendEncoder) ConfigureDefaultFormat(wo caddy.WriterOpener) error {
	if !fe.wrappedIsDefault {
		if cfd, ok := fe.wrapped.(caddy.ConfiguresFormatterDefault); ok {
			return cfd.ConfigureDefaultFormat(wo)
		}
		return nil
	}

	if caddy.IsWriterStandardStream(wo) && term.IsTerminal(int(os.Stderr.Fd())) {
		fe.wrapped = &ConsoleEncoder{}
		if p, ok := fe.wrapped.(caddy.Provisioner); ok {
			if err := p.Provision(fe.ctx); err != nil {
				return fmt.Errorf("provisioning fallback encoder module: %v", err)
			}
		}
	}
	return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	append {
//	    wrap <another encoder>
//	    fields {
//	        <field> <value>
//	    }
//	    <field> <value>
//	}
func (fe *AppendEncoder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume encoder name

	// parse a field
	parseField := func() error {
		if fe.Fields == nil {
			fe.Fields = make(map[string]any)
		}
		field := d.Val()
		if !d.NextArg() {
			return d.ArgErr()
		}
		fe.Fields[field] = d.ScalarVal()
		if d.NextArg() {
			return d.ArgErr()
		}
		return nil
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "wrap":
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
			fe.WrappedRaw = caddyconfig.JSONModuleObject(enc, "format", moduleName, nil)

		case "fields":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				err := parseField()
				if err != nil {
					return err
				}
			}

		default:
			// if unknown, assume it's a field so that
			// the config can be flat
			err := parseField()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// AddArray is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error {
	return fe.wrapped.AddArray(key, marshaler)
}

// AddObject is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error {
	return fe.wrapped.AddObject(key, marshaler)
}

// AddBinary is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddBinary(key string, value []byte) {
	fe.wrapped.AddBinary(key, value)
}

// AddByteString is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddByteString(key string, value []byte) {
	fe.wrapped.AddByteString(key, value)
}

// AddBool is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddBool(key string, value bool) {
	fe.wrapped.AddBool(key, value)
}

// AddComplex128 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddComplex128(key string, value complex128) {
	fe.wrapped.AddComplex128(key, value)
}

// AddComplex64 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddComplex64(key string, value complex64) {
	fe.wrapped.AddComplex64(key, value)
}

// AddDuration is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddDuration(key string, value time.Duration) {
	fe.wrapped.AddDuration(key, value)
}

// AddFloat64 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddFloat64(key string, value float64) {
	fe.wrapped.AddFloat64(key, value)
}

// AddFloat32 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddFloat32(key string, value float32) {
	fe.wrapped.AddFloat32(key, value)
}

// AddInt is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddInt(key string, value int) {
	fe.wrapped.AddInt(key, value)
}

// AddInt64 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddInt64(key string, value int64) {
	fe.wrapped.AddInt64(key, value)
}

// AddInt32 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddInt32(key string, value int32) {
	fe.wrapped.AddInt32(key, value)
}

// AddInt16 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddInt16(key string, value int16) {
	fe.wrapped.AddInt16(key, value)
}

// AddInt8 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddInt8(key string, value int8) {
	fe.wrapped.AddInt8(key, value)
}

// AddString is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddString(key, value string) {
	fe.wrapped.AddString(key, value)
}

// AddTime is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddTime(key string, value time.Time) {
	fe.wrapped.AddTime(key, value)
}

// AddUint is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddUint(key string, value uint) {
	fe.wrapped.AddUint(key, value)
}

// AddUint64 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddUint64(key string, value uint64) {
	fe.wrapped.AddUint64(key, value)
}

// AddUint32 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddUint32(key string, value uint32) {
	fe.wrapped.AddUint32(key, value)
}

// AddUint16 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddUint16(key string, value uint16) {
	fe.wrapped.AddUint16(key, value)
}

// AddUint8 is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddUint8(key string, value uint8) {
	fe.wrapped.AddUint8(key, value)
}

// AddUintptr is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddUintptr(key string, value uintptr) {
	fe.wrapped.AddUintptr(key, value)
}

// AddReflected is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) AddReflected(key string, value any) error {
	return fe.wrapped.AddReflected(key, value)
}

// OpenNamespace is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) OpenNamespace(key string) {
	fe.wrapped.OpenNamespace(key)
}

// Clone is part of the zapcore.ObjectEncoder interface.
func (fe AppendEncoder) Clone() zapcore.Encoder {
	return AppendEncoder{
		Fields:  fe.Fields,
		wrapped: fe.wrapped.Clone(),
		repl:    fe.repl,
	}
}

// EncodeEntry partially implements the zapcore.Encoder interface.
func (fe AppendEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	fe.wrapped = fe.wrapped.Clone()
	for _, field := range fields {
		field.AddTo(fe)
	}

	// append fields from config
	for key, value := range fe.Fields {
		// if the value is a string
		if str, ok := value.(string); ok {
			isPlaceholder := strings.HasPrefix(str, "{") &&
				strings.HasSuffix(str, "}") &&
				strings.Count(str, "{") == 1
			if isPlaceholder {
				// and it looks like a placeholder, evaluate it
				replaced, _ := fe.repl.Get(strings.Trim(str, "{}"))
				zap.Any(key, replaced).AddTo(fe)
			} else {
				// just use the string as-is
				zap.String(key, str).AddTo(fe)
			}
		} else {
			// not a string, so use the value as any
			zap.Any(key, value).AddTo(fe)
		}
	}

	return fe.wrapped.EncodeEntry(ent, nil)
}

// Interface guards
var (
	_ zapcore.Encoder                  = (*AppendEncoder)(nil)
	_ caddyfile.Unmarshaler            = (*AppendEncoder)(nil)
	_ caddy.ConfiguresFormatterDefault = (*AppendEncoder)(nil)
)
