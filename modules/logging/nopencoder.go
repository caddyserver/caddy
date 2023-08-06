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
func (nopEncoder) AddArray(_ string, _ zapcore.ArrayMarshaler) error { return nil }

// AddObject is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddObject(_ string, _ zapcore.ObjectMarshaler) error { return nil }

// AddBinary is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddBinary(_ string, _ []byte) {}

// AddByteString is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddByteString(_ string, _ []byte) {}

// AddBool is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddBool(_ string, _ bool) {}

// AddComplex128 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddComplex128(_ string, _ complex128) {}

// AddComplex64 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddComplex64(_ string, _ complex64) {}

// AddDuration is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddDuration(_ string, _ time.Duration) {}

// AddFloat64 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddFloat64(_ string, _ float64) {}

// AddFloat32 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddFloat32(_ string, _ float32) {}

// AddInt is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt(_ string, _ int) {}

// AddInt64 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt64(_ string, _ int64) {}

// AddInt32 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt32(_ string, _ int32) {}

// AddInt16 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt16(_ string, _ int16) {}

// AddInt8 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddInt8(_ string, _ int8) {}

// AddString is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddString(_, _ string) {}

// AddTime is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddTime(_ string, _ time.Time) {}

// AddUint is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint(_ string, _ uint) {}

// AddUint64 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint64(_ string, _ uint64) {}

// AddUint32 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint32(_ string, _ uint32) {}

// AddUint16 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint16(_ string, _ uint16) {}

// AddUint8 is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUint8(_ string, _ uint8) {}

// AddUintptr is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddUintptr(_ string, _ uintptr) {}

// AddReflected is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) AddReflected(_ string, _ any) error { return nil }

// OpenNamespace is part of the zapcore.ObjectEncoder interface.
func (nopEncoder) OpenNamespace(_ string) {}

// Clone is part of the zapcore.ObjectEncoder interface.
// We don't use it as of Oct 2019 (v2 beta 7), I'm not
// really sure what it'd be useful for in our case.
func (ne nopEncoder) Clone() zapcore.Encoder { return ne }

// EncodeEntry partially implements the zapcore.Encoder interface.
func (nopEncoder) EncodeEntry(_ zapcore.Entry, _ []zapcore.Field) (*buffer.Buffer, error) {
	return bufferpool.Get(), nil
}

// Interface guard
var _ zapcore.Encoder = (*nopEncoder)(nil)
