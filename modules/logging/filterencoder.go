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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(FilterEncoder{})
}

// FilterEncoder can filter (manipulate) fields on
// log entries before they are actually encoded by
// an underlying encoder.
type FilterEncoder struct {
	// The underlying encoder that actually
	// encodes the log entries. Required.
	WrappedRaw json.RawMessage `json:"wrap,omitempty" caddy:"namespace=caddy.logging.encoders inline_key=format"`

	// A map of field names to their filters. Note that this
	// is not a module map; the keys are field names.
	//
	// Nested fields can be referenced by representing a
	// layer of nesting with `>`. In other words, for an
	// object like `{"a":{"b":0}}`, the inner field can
	// be referenced as `a>b`.
	//
	// The following fields are fundamental to the log and
	// cannot be filtered because they are added by the
	// underlying logging library as special cases: ts,
	// level, logger, and msg.
	FieldsRaw map[string]json.RawMessage `json:"fields,omitempty" caddy:"namespace=caddy.logging.encoders.filter inline_key=filter"`

	wrapped zapcore.Encoder
	Fields  map[string]LogFieldFilter `json:"-"`

	// used to keep keys unique across nested objects
	keyPrefix string
}

// CaddyModule returns the Caddy module information.
func (FilterEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter",
		New: func() caddy.Module { return new(FilterEncoder) },
	}
}

// Provision sets up the encoder.
func (fe *FilterEncoder) Provision(ctx caddy.Context) error {
	if fe.WrappedRaw == nil {
		return fmt.Errorf("missing \"wrap\" (must specify an underlying encoder)")
	}

	// set up wrapped encoder (required)
	val, err := ctx.LoadModule(fe, "WrappedRaw")
	if err != nil {
		return fmt.Errorf("loading fallback encoder module: %v", err)
	}
	fe.wrapped = val.(zapcore.Encoder)

	// set up each field filter
	if fe.Fields == nil {
		fe.Fields = make(map[string]LogFieldFilter)
	}
	vals, err := ctx.LoadModule(fe, "FieldsRaw")
	if err != nil {
		return fmt.Errorf("loading log filter modules: %v", err)
	}
	for fieldName, modIface := range vals.(map[string]interface{}) {
		fe.Fields[fieldName] = modIface.(LogFieldFilter)
	}

	return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//     filter {
//         wrap <another encoder>
//         fields {
//             <field> <filter> {
//                 <filter options>
//             }
//         }
//     }
func (fe *FilterEncoder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "wrap":
				if !d.NextArg() {
					return d.ArgErr()
				}
				moduleName := d.Val()
				mod, err := caddy.GetModule("caddy.logging.encoders." + moduleName)
				if err != nil {
					return d.Errf("getting log encoder module named '%s': %v", moduleName, err)
				}
				unm, ok := mod.New().(caddyfile.Unmarshaler)
				if !ok {
					return d.Errf("log encoder module '%s' is not a Caddyfile unmarshaler", mod)
				}
				err = unm.UnmarshalCaddyfile(d.NewFromNextSegment())
				if err != nil {
					return err
				}
				enc, ok := unm.(zapcore.Encoder)
				if !ok {
					return d.Errf("module %s is not a zapcore.Encoder", mod)
				}
				fe.WrappedRaw = caddyconfig.JSONModuleObject(enc, "format", moduleName, nil)

			case "fields":
				for d.NextBlock(1) {
					field := d.Val()
					if !d.NextArg() {
						return d.ArgErr()
					}
					filterName := d.Val()
					mod, err := caddy.GetModule("caddy.logging.encoders.filter." + filterName)
					if err != nil {
						return d.Errf("getting log filter module named '%s': %v", filterName, err)
					}
					unm, ok := mod.New().(caddyfile.Unmarshaler)
					if !ok {
						return d.Errf("log encoder module '%s' is not a Caddyfile unmarshaler", mod)
					}
					err = unm.UnmarshalCaddyfile(d.NewFromNextSegment())
					if err != nil {
						return err
					}
					f, ok := unm.(LogFieldFilter)
					if !ok {
						return d.Errf("module %s is not a LogFieldFilter", mod)
					}
					if fe.FieldsRaw == nil {
						fe.FieldsRaw = make(map[string]json.RawMessage)
					}
					fe.FieldsRaw[field] = caddyconfig.JSONModuleObject(f, "filter", filterName, nil)
				}

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
		}
	}
	return nil
}

// AddArray is part of the zapcore.ObjectEncoder interface.
// Array elements do not get filtered.
func (fe FilterEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error {
	if filter, ok := fe.Fields[fe.keyPrefix+key]; ok {
		filter.Filter(zap.Array(key, marshaler)).AddTo(fe.wrapped)
		return nil
	}
	return fe.wrapped.AddArray(key, marshaler)
}

// AddObject is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error {
	if fe.filtered(key, marshaler) {
		return nil
	}
	fe.keyPrefix += key + ">"
	return fe.wrapped.AddObject(key, logObjectMarshalerWrapper{
		enc:   fe,
		marsh: marshaler,
	})
}

// AddBinary is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddBinary(key string, value []byte) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddBinary(key, value)
	}
}

// AddByteString is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddByteString(key string, value []byte) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddByteString(key, value)
	}
}

// AddBool is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddBool(key string, value bool) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddBool(key, value)
	}
}

// AddComplex128 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddComplex128(key string, value complex128) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddComplex128(key, value)
	}
}

// AddComplex64 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddComplex64(key string, value complex64) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddComplex64(key, value)
	}
}

// AddDuration is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddDuration(key string, value time.Duration) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddDuration(key, value)
	}
}

// AddFloat64 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddFloat64(key string, value float64) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddFloat64(key, value)
	}
}

// AddFloat32 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddFloat32(key string, value float32) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddFloat32(key, value)
	}
}

// AddInt is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddInt(key string, value int) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddInt(key, value)
	}
}

// AddInt64 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddInt64(key string, value int64) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddInt64(key, value)
	}
}

// AddInt32 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddInt32(key string, value int32) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddInt32(key, value)
	}
}

// AddInt16 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddInt16(key string, value int16) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddInt16(key, value)
	}
}

// AddInt8 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddInt8(key string, value int8) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddInt8(key, value)
	}
}

// AddString is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddString(key, value string) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddString(key, value)
	}
}

// AddTime is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddTime(key string, value time.Time) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddTime(key, value)
	}
}

// AddUint is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddUint(key string, value uint) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddUint(key, value)
	}
}

// AddUint64 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddUint64(key string, value uint64) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddUint64(key, value)
	}
}

// AddUint32 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddUint32(key string, value uint32) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddUint32(key, value)
	}
}

// AddUint16 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddUint16(key string, value uint16) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddUint16(key, value)
	}
}

// AddUint8 is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddUint8(key string, value uint8) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddUint8(key, value)
	}
}

// AddUintptr is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddUintptr(key string, value uintptr) {
	if !fe.filtered(key, value) {
		fe.wrapped.AddUintptr(key, value)
	}
}

// AddReflected is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) AddReflected(key string, value interface{}) error {
	if !fe.filtered(key, value) {
		return fe.wrapped.AddReflected(key, value)
	}
	return nil
}

// OpenNamespace is part of the zapcore.ObjectEncoder interface.
func (fe FilterEncoder) OpenNamespace(key string) {
	fe.wrapped.OpenNamespace(key)
}

// Clone is part of the zapcore.ObjectEncoder interface.
// We don't use it as of Oct 2019 (v2 beta 7), I'm not
// really sure what it'd be useful for in our case.
func (fe FilterEncoder) Clone() zapcore.Encoder {
	return FilterEncoder{
		Fields:    fe.Fields,
		wrapped:   fe.wrapped.Clone(),
		keyPrefix: fe.keyPrefix,
	}
}

// EncodeEntry partially implements the zapcore.Encoder interface.
func (fe FilterEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	// without this clone and storing it to fe.wrapped, fields
	// from subsequent log entries get appended to previous
	// ones, and I'm not 100% sure why; see end of
	// https://github.com/uber-go/zap/issues/750
	fe.wrapped = fe.wrapped.Clone()
	for _, field := range fields {
		field.AddTo(fe)
	}
	return fe.wrapped.EncodeEntry(ent, nil)
}

// filtered returns true if the field was filtered.
// If true is returned, the field was filtered and
// added to the underlying encoder (so do not do
// that again). If false was returned, the field has
// not yet been added to the underlying encoder.
func (fe FilterEncoder) filtered(key string, value interface{}) bool {
	filter, ok := fe.Fields[fe.keyPrefix+key]
	if !ok {
		return false
	}
	filter.Filter(zap.Any(key, value)).AddTo(fe.wrapped)
	return true
}

// logObjectMarshalerWrapper allows us to recursively
// filter fields of objects as they get encoded.
type logObjectMarshalerWrapper struct {
	enc   FilterEncoder
	marsh zapcore.ObjectMarshaler
}

// MarshalLogObject implements the zapcore.ObjectMarshaler interface.
func (mom logObjectMarshalerWrapper) MarshalLogObject(_ zapcore.ObjectEncoder) error {
	return mom.marsh.MarshalLogObject(mom.enc)
}

// Interface guards
var (
	_ zapcore.Encoder         = (*FilterEncoder)(nil)
	_ zapcore.ObjectMarshaler = (*logObjectMarshalerWrapper)(nil)
	_ caddyfile.Unmarshaler   = (*FilterEncoder)(nil)
)
