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

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(ConsoleEncoder{})
	caddy.RegisterModule(JSONEncoder{})
}

// ConsoleEncoder encodes log entries that are mostly human-readable.
type ConsoleEncoder struct {
	zapcore.Encoder `json:"-"`
	LogEncoderConfig
}

// CaddyModule returns the Caddy module information.
func (ConsoleEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.console",
		New: func() caddy.Module { return new(ConsoleEncoder) },
	}
}

// Provision sets up the encoder.
func (ce *ConsoleEncoder) Provision(_ caddy.Context) error {
	if ce.LevelFormat == "" {
		ce.LevelFormat = "color"
	}
	if ce.TimeFormat == "" {
		ce.TimeFormat = "wall_milli"
	}
	ce.Encoder = zapcore.NewConsoleEncoder(ce.ZapcoreEncoderConfig())
	return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	console {
//	    <common encoder config subdirectives...>
//	}
//
// See the godoc on the LogEncoderConfig type for the syntax of
// subdirectives that are common to most/all encoders.
func (ce *ConsoleEncoder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume encoder name
	if d.NextArg() {
		return d.ArgErr()
	}
	err := ce.LogEncoderConfig.UnmarshalCaddyfile(d)
	if err != nil {
		return err
	}
	return nil
}

// JSONEncoder encodes entries as JSON.
type JSONEncoder struct {
	zapcore.Encoder `json:"-"`
	LogEncoderConfig
}

// CaddyModule returns the Caddy module information.
func (JSONEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.json",
		New: func() caddy.Module { return new(JSONEncoder) },
	}
}

// Provision sets up the encoder.
func (je *JSONEncoder) Provision(_ caddy.Context) error {
	je.Encoder = zapcore.NewJSONEncoder(je.ZapcoreEncoderConfig())
	return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	json {
//	    <common encoder config subdirectives...>
//	}
//
// See the godoc on the LogEncoderConfig type for the syntax of
// subdirectives that are common to most/all encoders.
func (je *JSONEncoder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume encoder name
	if d.NextArg() {
		return d.ArgErr()
	}
	err := je.LogEncoderConfig.UnmarshalCaddyfile(d)
	if err != nil {
		return err
	}
	return nil
}

// LogEncoderConfig holds configuration common to most encoders.
type LogEncoderConfig struct {
	MessageKey    *string `json:"message_key,omitempty"`
	LevelKey      *string `json:"level_key,omitempty"`
	TimeKey       *string `json:"time_key,omitempty"`
	NameKey       *string `json:"name_key,omitempty"`
	CallerKey     *string `json:"caller_key,omitempty"`
	StacktraceKey *string `json:"stacktrace_key,omitempty"`
	LineEnding    *string `json:"line_ending,omitempty"`

	// Recognized values are: unix_seconds_float, unix_milli_float, unix_nano, iso8601, rfc3339, rfc3339_nano, wall, wall_milli, wall_nano, common_log.
	// The value may also be custom format per the Go `time` package layout specification, as described [here](https://pkg.go.dev/time#pkg-constants).
	TimeFormat string `json:"time_format,omitempty"`
	TimeLocal  bool   `json:"time_local,omitempty"`

	// Recognized values are: s/second/seconds, ns/nano/nanos, ms/milli/millis, string.
	// Empty and unrecognized value default to seconds.
	DurationFormat string `json:"duration_format,omitempty"`

	// Recognized values are: lower, upper, color.
	// Empty and unrecognized value default to lower.
	LevelFormat string `json:"level_format,omitempty"`
}

// UnmarshalCaddyfile populates the struct from Caddyfile tokens. Syntax:
//
//	{
//	    message_key     <key>
//	    level_key       <key>
//	    time_key        <key>
//	    name_key        <key>
//	    caller_key      <key>
//	    stacktrace_key  <key>
//	    line_ending     <char>
//	    time_format     <format>
//	    time_local
//	    duration_format <format>
//	    level_format    <format>
//	}
func (lec *LogEncoderConfig) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.NextBlock(0) {
		subdir := d.Val()
		switch subdir {
		case "time_local":
			lec.TimeLocal = true
			if d.NextArg() {
				return d.ArgErr()
			}
			continue
		}
		var arg string
		if !d.AllArgs(&arg) {
			return d.ArgErr()
		}
		switch subdir {
		case "message_key":
			lec.MessageKey = &arg
		case "level_key":
			lec.LevelKey = &arg
		case "time_key":
			lec.TimeKey = &arg
		case "name_key":
			lec.NameKey = &arg
		case "caller_key":
			lec.CallerKey = &arg
		case "stacktrace_key":
			lec.StacktraceKey = &arg
		case "line_ending":
			lec.LineEnding = &arg
		case "time_format":
			lec.TimeFormat = arg
		case "duration_format":
			lec.DurationFormat = arg
		case "level_format":
			lec.LevelFormat = arg
		default:
			return d.Errf("unrecognized subdirective %s", subdir)
		}
	}
	return nil
}

// ZapcoreEncoderConfig returns the equivalent zapcore.EncoderConfig.
// If lec is nil, zap.NewProductionEncoderConfig() is returned.
func (lec *LogEncoderConfig) ZapcoreEncoderConfig() zapcore.EncoderConfig {
	cfg := zap.NewProductionEncoderConfig()
	if lec == nil {
		lec = new(LogEncoderConfig)
	}
	if lec.MessageKey != nil {
		cfg.MessageKey = *lec.MessageKey
	}
	if lec.LevelKey != nil {
		cfg.LevelKey = *lec.LevelKey
	}
	if lec.TimeKey != nil {
		cfg.TimeKey = *lec.TimeKey
	}
	if lec.NameKey != nil {
		cfg.NameKey = *lec.NameKey
	}
	if lec.CallerKey != nil {
		cfg.CallerKey = *lec.CallerKey
	}
	if lec.StacktraceKey != nil {
		cfg.StacktraceKey = *lec.StacktraceKey
	}
	if lec.LineEnding != nil {
		cfg.LineEnding = *lec.LineEnding
	}

	// time format
	var timeFormatter zapcore.TimeEncoder
	switch lec.TimeFormat {
	case "", "unix_seconds_float":
		timeFormatter = zapcore.EpochTimeEncoder
	case "unix_milli_float":
		timeFormatter = zapcore.EpochMillisTimeEncoder
	case "unix_nano":
		timeFormatter = zapcore.EpochNanosTimeEncoder
	case "iso8601":
		timeFormatter = zapcore.ISO8601TimeEncoder
	default:
		timeFormat := lec.TimeFormat
		switch lec.TimeFormat {
		case "rfc3339":
			timeFormat = time.RFC3339
		case "rfc3339_nano":
			timeFormat = time.RFC3339Nano
		case "wall":
			timeFormat = "2006/01/02 15:04:05"
		case "wall_milli":
			timeFormat = "2006/01/02 15:04:05.000"
		case "wall_nano":
			timeFormat = "2006/01/02 15:04:05.000000000"
		case "common_log":
			timeFormat = "02/Jan/2006:15:04:05 -0700"
		}
		timeFormatter = func(ts time.Time, encoder zapcore.PrimitiveArrayEncoder) {
			var time time.Time
			if lec.TimeLocal {
				time = ts.Local()
			} else {
				time = ts.UTC()
			}
			encoder.AppendString(time.Format(timeFormat))
		}
	}
	cfg.EncodeTime = timeFormatter

	// duration format
	var durFormatter zapcore.DurationEncoder
	switch lec.DurationFormat {
	case "s", "second", "seconds":
		durFormatter = zapcore.SecondsDurationEncoder
	case "ns", "nano", "nanos":
		durFormatter = zapcore.NanosDurationEncoder
	case "ms", "milli", "millis":
		durFormatter = zapcore.MillisDurationEncoder
	case "string":
		durFormatter = zapcore.StringDurationEncoder
	default:
		durFormatter = zapcore.SecondsDurationEncoder
	}
	cfg.EncodeDuration = durFormatter

	// level format
	var levelFormatter zapcore.LevelEncoder
	switch lec.LevelFormat {
	case "", "lower":
		levelFormatter = zapcore.LowercaseLevelEncoder
	case "upper":
		levelFormatter = zapcore.CapitalLevelEncoder
	case "color":
		levelFormatter = zapcore.CapitalColorLevelEncoder
	}
	cfg.EncodeLevel = levelFormatter

	return cfg
}

var bufferpool = buffer.NewPool()

// Interface guards
var (
	_ zapcore.Encoder = (*ConsoleEncoder)(nil)
	_ zapcore.Encoder = (*JSONEncoder)(nil)

	_ caddyfile.Unmarshaler = (*ConsoleEncoder)(nil)
	_ caddyfile.Unmarshaler = (*JSONEncoder)(nil)
)
