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

// TestFlushLogs verifies that FlushLogs writes buffered entries to the
// original default logger, so startup errors logged through a buffered
// default logger are not silently lost when the process exits.
func TestFlushLogs(t *testing.T) {
	const errMsg = "startup failed: config is invalid"

	// setup installs a default logger that writes to an in-memory buffer
	// standing in for the real (stderr) default logger, and registers the
	// restore via t.Cleanup so that it still runs when a case fails; leaving
	// the global swapped would silently corrupt every later test in this
	// package. It returns the buffer the restored-by-BufferedLog entries
	// should end up in.
	setup := func(t *testing.T) *bytes.Buffer {
		t.Helper()

		var buf bytes.Buffer
		encoder := zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
		origLogger := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.InfoLevel))

		defaultLoggerMu.Lock()
		savedLogger := defaultLogger
		defaultLogger = &defaultCustomLog{logger: origLogger}
		defaultLoggerMu.Unlock()

		t.Cleanup(func() {
			defaultLoggerMu.Lock()
			defaultLogger = savedLogger
			defaultLoggerMu.Unlock()
		})

		return &buf
	}

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
			buf := setup(t)

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
		setup(t)
		FlushLogs()
	})

	t.Run("no-op without a destination", func(t *testing.T) {
		setup(t)

		// a buffer created with no destination has nowhere to write to, so
		// flushing it must leave the entries alone rather than panic
		defaultLoggerMu.Lock()
		defaultLogger.logger = zap.New(internal.NewLogBufferCore(zap.InfoLevel, nil))
		defaultLoggerMu.Unlock()

		Log().Error(errMsg)
		FlushLogs()
	})
}

// TestFlushLogsConcurrency checks that FlushLogs is safe to call from several
// goroutines while entries are still being written, and that buffering twice
// does not leave a flush writing into the buffer it is draining.
func TestFlushLogsConcurrency(t *testing.T) {
	const messageCount = 64

	// install is the same setup as TestFlushLogs: the "real" default logger
	// writes into buf, and the restore is registered with t.Cleanup.
	install := func(t *testing.T) *bytes.Buffer {
		t.Helper()

		var buf bytes.Buffer
		encoder := zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
		origLogger := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.InfoLevel))

		defaultLoggerMu.Lock()
		savedLogger := defaultLogger
		defaultLogger = &defaultCustomLog{logger: origLogger}
		defaultLoggerMu.Unlock()

		t.Cleanup(func() {
			defaultLoggerMu.Lock()
			defaultLogger = savedLogger
			defaultLoggerMu.Unlock()
		})

		return &buf
	}

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
		buf := install(t)
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

	// BufferedLog is not idempotent: calling it twice leaves the first buffer
	// unreachable. Each buffer owns its own destination, so the second flush
	// writes into the first buffer rather than into itself, which is what
	// keeps it from deadlocking on the non-reentrant buffer mutex. What this
	// guards is termination: if it ever hangs, the go test timeout is what
	// catches it.
	t.Run("flushing after buffering twice terminates", func(t *testing.T) {
		install(t)
		BufferedLog()
		BufferedLog()
		Log().Error("entry in the second buffer")
		FlushLogs()
	})
}
