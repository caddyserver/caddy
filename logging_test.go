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

// TestFlushLogs verifies that FlushLogs writes buffered entries to the
// original default logger, so startup errors logged through a buffered
// default logger are not silently lost when the process exits.
func TestFlushLogs(t *testing.T) {
	// set up a buffer that acts as the "original" default logger target
	var buf bytes.Buffer
	encoder := zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.InfoLevel)
	origLogger := zap.New(core)

	// swap the default logger to a buffered one, remembering the original
	defaultLoggerMu.Lock()
	savedLogger := defaultLogger
	savedOrig := bufferedLogOrig
	defaultLogger = &defaultCustomLog{logger: origLogger}
	bufferedLogOrig = origLogger
	defaultLoggerMu.Unlock()

	buffered, _, _ := BufferedLog()

	// log through the buffered logger; nothing should be written yet
	buffered.Error("startup failed: config is invalid")
	if buf.Len() != 0 {
		t.Fatalf("expected buffered log to not be written yet, got %q", buf.String())
	}

	// flush should write the buffered entry to the original logger target
	FlushLogs()

	// and the entry should have been written to the original output
	if !strings.Contains(buf.String(), "startup failed: config is invalid") {
		t.Fatalf("expected flushed log to contain error message, got %q", buf.String())
	}

	// flushing again must be a no-op (the buffer was drained), so the
	// entry is not duplicated
	FlushLogs()
	if got := strings.Count(buf.String(), "startup failed: config is invalid"); got != 1 {
		t.Fatalf("expected error message exactly once after second flush, got %d occurrences in %q", got, buf.String())
	}

	// restore global state
	defaultLoggerMu.Lock()
	defaultLogger = savedLogger
	bufferedLogOrig = savedOrig
	defaultLoggerMu.Unlock()
}
