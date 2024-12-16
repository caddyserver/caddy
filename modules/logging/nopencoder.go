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
	"time"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// nopEncoder is a zapcore.Encoder that does nothing.
type nopEncoder struct{}

// AddArray is part of the zapcore.ObjectEncoder interface.
// Array elements do not get filtered.
func (nopEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error { return nil }

// AddObject is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error { return nil }

// AddBinary is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddBinary(key string, value []byte) {}

// AddByteString is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddByteString(key string, value []byte) {}

// AddBool is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddBool(key string, value bool) {}

// AddComplex128 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddComplex128(key string, value complex128) {}

// AddComplex64 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddComplex64(key string, value complex64) {}

// AddDuration is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddDuration(key string, value time.Duration) {}

// AddFloat64 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddFloat64(key string, value float64) {}

// AddFloat32 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddFloat32(key string, value float32) {}

// AddInt is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt(key string, value int) {}

// AddInt64 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt64(key string, value int64) {}

// AddInt32 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt32(key string, value int32) {}

// AddInt16 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt16(key string, value int16) {}

// AddInt8 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt8(key string, value int8) {}

// AddString is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddString(key, value string) {}

// AddTime is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddTime(key string, value time.Time) {}

// AddUint is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint(key string, value uint) {}

// AddUint64 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint64(key string, value uint64) {}

// AddUint32 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint32(key string, value uint32) {}

// AddUint16 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint16(key string, value uint16) {}

// AddUint8 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint8(key string, value uint8) {}

// AddUintptr is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUintptr(key string, value uintptr) {}

// AddReflected is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddReflected(key string, value any) error { return nil }

// OpenNamespace is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) OpenNamespace(key string) {}

// Clone is part of the zapcore.ObjectEncoder interface.
// We don't use it as of Oct 2019 (v2 beta 7), I'm not
// really sure what it'd be useful for in our case.
func (ne nopEncoder) Clone() zapcore.Encoder { return ne }

// EncodeEntry partially implements the zapcore.Encoder interface.
func (nopEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	return bufferpool.Get(), nil
}

// Interface guard
var _ zapcore.Encoder = (*nopEncoder)(nil)
