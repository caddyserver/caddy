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
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/internal"
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

// swapDefaultLoggerForTest points the default logger at a console logger that
// writes into buf, standing in for the real (stderr) default logger, and
// restores the original when the test ends. The restore is registered with
// t.Cleanup so that it still runs when a case fails; leaving the global swapped
// would silently corrupt every later test in this package.
func swapDefaultLoggerForTest(t *testing.T, buf *bytes.Buffer) {
	t.Helper()

	encoder := zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
	origLogger := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(buf), zapcore.InfoLevel))

	defaultLoggerMu.Lock()
	savedLogger := defaultLogger
	defaultLogger = &defaultCustomLog{logger: origLogger}
	defaultLoggerMu.Unlock()

	t.Cleanup(func() {
		defaultLoggerMu.Lock()
		defaultLogger = savedLogger
		defaultLoggerMu.Unlock()
	})
}

// TestFlushLogs verifies that FlushLogs writes buffered entries to the
// original default logger, so startup errors logged through a buffered
// default logger are not silently lost when the process exits.
func TestFlushLogs(t *testing.T) {
	const errMsg = "startup failed: config is invalid"

	tests := []struct {
		name string
		// wantWritten is how many times errMsg must appear in the
		// original logger's output after the case runs.
		wantWritten int
		// logErr logs an error through the buffered default logger.
		logErr bool
		// flushes is how many times FlushLogs is called.
		flushes int
	}{
		{
			name:        "buffered entry is withheld until flushed",
			logErr:      true,
			flushes:     0,
			wantWritten: 0,
		},
		{
			name:        "flushed entry reaches the original logger",
			logErr:      true,
			flushes:     1,
			wantWritten: 1,
		},
		{
			name:        "flushing twice does not duplicate the entry",
			logErr:      true,
			flushes:     2,
			wantWritten: 1,
		},
		{
			name:        "flushing an empty buffer is harmless",
			logErr:      false,
			flushes:     1,
			wantWritten: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			swapDefaultLoggerForTest(t, buf)

			// BufferedLog returns the buffered logger, the original
			// default logger, and the buffer core itself.
			buffered, _, _ := BufferedLog()

			if tt.logErr {
				buffered.Error(errMsg)
			}
			for range tt.flushes {
				FlushLogs()
			}

			if got := strings.Count(buf.String(), errMsg); got != tt.wantWritten {
				t.Errorf("error message written %d time(s) to the original logger, want %d; output was %q",
					got, tt.wantWritten, buf.String())
			}
		})
	}

	// FlushLogs must not panic when the default logger is not buffered,
	// which is the case for every command that never calls BufferedLog,
	// and when there is no remembered destination to flush to.
	t.Run("no-op when not buffered", func(t *testing.T) {
		swapDefaultLoggerForTest(t, &bytes.Buffer{})
		FlushLogs()
	})

	t.Run("no-op without a destination", func(t *testing.T) {
		buf := &bytes.Buffer{}
		swapDefaultLoggerForTest(t, buf)

		// a buffer created with no destination has nowhere to write to, so
		// flushing it must leave the entries alone rather than panic or
		// drop them
		defaultLoggerMu.Lock()
		defaultLogger.logger = zap.New(internal.NewLogBufferCore(zap.InfoLevel, nil))
		defaultLoggerMu.Unlock()

		Log().Error(errMsg)
		FlushLogs()

		if buf.Len() != 0 {
			t.Errorf("a buffer with no destination wrote %q, want nothing written", buf.String())
		}
	})

	// BufferedLog is expected to be called once, but a second call nests
	// buffers: the new buffer's destination is the previous buffer's logger.
	// A flush then has to walk past that buffer to the real logger rather
	// than writing back into it, which would leave both entries stuck in a
	// buffer nobody can reach.
	t.Run("entries escape a nested buffer", func(t *testing.T) {
		buf := &bytes.Buffer{}
		swapDefaultLoggerForTest(t, buf)

		BufferedLog()
		Log().Error("first entry")
		BufferedLog()
		Log().Error("second entry")

		FlushLogs()

		// both entries belong to different buffers, so neither is a substring
		// of the other and Count of 1 means each reached the original logger
		// exactly once
		for _, msg := range []string{"first entry", "second entry"} {
			if got := strings.Count(buf.String(), msg); got != 1 {
				t.Errorf("message %q reached the original logger %d time(s), want exactly 1; output was %q",
					msg, got, buf.String())
			}
		}
	})
}

// TestFlushLogsConcurrency checks that FlushLogs is safe to call from several
// goroutines while entries are still being written.
func TestFlushLogsConcurrency(t *testing.T) {
	const messageCount = 64

	messages := make([]string, messageCount)
	for i := range messages {
		// zero-pad so that no message is a prefix of another, otherwise
		// strings.Count would also match entries 10..19 for entry 1
		messages[i] = fmt.Sprintf("concurrent entry %03d", i)
	}

	// every message is written exactly once, so after a final flush each one
	// must appear exactly once: Flush drains the buffer it is called on, so
	// concurrent flushes cannot duplicate or drop entries
	t.Run("flushes while entries are written", func(t *testing.T) {
		buf := &bytes.Buffer{}
		swapDefaultLoggerForTest(t, buf)
		BufferedLog()

		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, msg := range messages {
				Log().Error(msg)
			}
		}()

		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 32 {
					FlushLogs()
				}
			}()
		}

		wg.Wait()
		FlushLogs()

		for _, msg := range messages {
			if got := strings.Count(buf.String(), msg); got != 1 {
				t.Fatalf("message %q written %d time(s), want exactly 1", msg, got)
			}
		}
	})
}
