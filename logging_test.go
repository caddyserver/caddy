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

// TestFlushLogs verifies that FlushLogs writes out entries still held in the
// startup buffer and then restores the logger the buffer had replaced. Both
// halves matter: without the flush the entries are lost, and without the
// restore anything logged afterwards lands in an empty buffer that nobody is
// left to drain.
func TestFlushLogs(t *testing.T) {
	const errMsg = "startup failed: config is invalid"

	for _, tc := range []struct {
		name string
		// buffered installs a startup buffer on top of a default logger that
		// writes into buf, standing in for the real (stderr) default logger.
		buffered bool
		// wantWritten is how many times errMsg must appear in buf afterwards.
		wantWritten int
		// wantBuffered is whether the default logger must still be buffered
		// when FlushLogs returns.
		wantBuffered bool
	}{
		{
			name:         "buffered entries are written out and the logger restored",
			buffered:     true,
			wantWritten:  1,
			wantBuffered: false,
		},
		{
			name:         "no buffer installed is a no-op",
			buffered:     false,
			wantWritten:  0,
			wantBuffered: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			encoder := zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
			origLogger := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.InfoLevel))

			defaultLoggerMu.Lock()
			savedLogger, savedOrig := defaultLogger, bufferedLogOrig
			defaultLogger = &defaultCustomLog{logger: origLogger}
			bufferedLogOrig = nil
			defaultLoggerMu.Unlock()

			// Restore the globals afterwards even if the case fails; leaving
			// them swapped would corrupt every later test in this package.
			t.Cleanup(func() {
				defaultLoggerMu.Lock()
				defaultLogger, bufferedLogOrig = savedLogger, savedOrig
				defaultLoggerMu.Unlock()
			})

			if tc.buffered {
				buffered, _, _ := BufferedLog()
				buffered.Error(errMsg)

				// the entry must still be held back before the flush
				if strings.Contains(buf.String(), errMsg) {
					t.Fatalf("entry reached the original logger before being flushed: %q", buf.String())
				}
			}

			FlushLogs()

			if got := strings.Count(buf.String(), errMsg); got != tc.wantWritten {
				t.Errorf("error message written %d time(s), want %d; output was %q",
					got, tc.wantWritten, buf.String())
			}

			_, isBuffered := Log().Core().(*internal.LogBufferCore)
			if isBuffered != tc.wantBuffered {
				t.Errorf("default logger still buffered after FlushLogs: %v, want %v",
					isBuffered, tc.wantBuffered)
			}
		})
	}

	// Once the buffer has been flushed and restored, later entries must go
	// straight to the original logger instead of into a buffer nobody drains.
	t.Run("entries after the flush are not stranded", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
		origLogger := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.InfoLevel))

		defaultLoggerMu.Lock()
		savedLogger, savedOrig := defaultLogger, bufferedLogOrig
		defaultLogger = &defaultCustomLog{logger: origLogger}
		bufferedLogOrig = nil
		defaultLoggerMu.Unlock()

		t.Cleanup(func() {
			defaultLoggerMu.Lock()
			defaultLogger, bufferedLogOrig = savedLogger, savedOrig
			defaultLoggerMu.Unlock()
		})

		buffered, _, _ := BufferedLog()
		buffered.Error("before flush")
		FlushLogs()
		Log().Error("after flush")

		if got := strings.Count(buf.String(), "after flush"); got != 1 {
			t.Errorf("entry logged after the flush appeared %d time(s), want 1; output was %q",
				got, buf.String())
		}
	})
}
