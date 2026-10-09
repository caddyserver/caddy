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

package caddy

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2/internal"
)

func TestCustomLog_loggerAllowed(t *testing.T) {
	type fields struct {
		BaseLog BaseLog
		Include []string
		Exclude []string
	}
	type args struct {
		name     string
		isModule bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "include",
			fields: fields{
				Include: []string{"foo"},
			},
			args: args{
				name:     "foo",
				isModule: true,
			},
			want: true,
		},
		{
			name: "exclude",
			fields: fields{
				Exclude: []string{"foo"},
			},
			args: args{
				name:     "foo",
				isModule: true,
			},
			want: false,
		},
		{
			name: "include and exclude",
			fields: fields{
				Include: []string{"foo"},
				Exclude: []string{"foo"},
			},
			args: args{
				name:     "foo",
				isModule: true,
			},
			want: false,
		},
		{
			name: "include and exclude (longer namespace)",
			fields: fields{
				Include: []string{"foo.bar"},
				Exclude: []string{"foo"},
			},
			args: args{
				name:     "foo.bar",
				isModule: true,
			},
			want: true,
		},
		{
			name: "excluded module is not printed",
			fields: fields{
				Include: []string{"admin.api.load"},
				Exclude: []string{"admin.api"},
			},
			args: args{
				name:     "admin.api",
				isModule: false,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := &CustomLog{
				BaseLog: tt.fields.BaseLog,
				Include: tt.fields.Include,
				Exclude: tt.fields.Exclude,
			}
			if got := cl.loggerAllowed(tt.args.name, tt.args.isModule); got != tt.want {
				t.Errorf("CustomLog.loggerAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnbufferDefaultLogger(t *testing.T) {
	defaultLoggerMu.RLock()
	origDefault := defaultLogger
	defaultLoggerMu.RUnlock()
	t.Cleanup(func() {
		defaultLoggerMu.Lock()
		defaultLogger = origDefault
		defaultLoggerMu.Unlock()
	})

	// Set up an observing logger to verify buffer flushing and post-unbuffer logging
	buf := new(bytes.Buffer)
	destCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.AddSync(buf),
		zapcore.InfoLevel,
	)
	destLogger := zap.New(destCore)

	defaultLoggerMu.Lock()
	defaultLogger = &defaultCustomLog{
		CustomLog: &CustomLog{},
		logger:    destLogger,
	}
	defaultLoggerMu.Unlock()

	// 1. Engage buffered logging
	bufferedLogger, origLogger, _ := BufferedLog()

	// Verify default logger is now using the buffer core
	if _, ok := Log().Core().(*internal.LogBufferCore); !ok {
		t.Fatal("expected default logger core to be *internal.LogBufferCore")
	}

	// 2. Log while buffered
	bufferedLogger.Info("early startup log message")

	// Messages should not be written to destination yet while buffered
	if buf.Len() > 0 {
		t.Fatalf("expected destination buffer to be empty while buffered, got: %s", buf.String())
	}

	// 3. Unbuffer the default logger
	UnbufferDefaultLogger(origLogger)

	// Verify default logger core is no longer LogBufferCore
	if _, ok := Log().Core().(*internal.LogBufferCore); ok {
		t.Fatal("expected default logger core to no longer be *internal.LogBufferCore after UnbufferDefaultLogger")
	}

	// Verify early buffered logs were flushed to destination logger
	if !strings.Contains(buf.String(), "early startup log message") {
		t.Fatalf("expected destination buffer to contain early startup log message, got: %s", buf.String())
	}

	// 4. Log after unbuffering: should go directly to destination logger, not swallowed
	Log().Error("startup failed error")
	if !strings.Contains(buf.String(), "startup failed error") {
		t.Fatalf("expected destination buffer to contain error message, got: %s", buf.String())
	}

	// 5. Calling UnbufferDefaultLogger again when not buffered should be a safe no-op
	UnbufferDefaultLogger(origLogger)
	if _, ok := Log().Core().(*internal.LogBufferCore); ok {
		t.Fatal("unexpected buffer core after second unbuffer call")
	}
}
